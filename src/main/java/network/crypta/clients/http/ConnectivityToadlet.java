package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.endpoints.http.ConnectivityPagePaths;
import network.crypta.runtime.spi.ConnectivityGapSnapshot;
import network.crypta.runtime.spi.ConnectivityListenerPortSnapshot;
import network.crypta.runtime.spi.ConnectivityNoticeSnapshot;
import network.crypta.runtime.spi.ConnectivityPort;
import network.crypta.runtime.spi.ConnectivityPortForwardStatus;
import network.crypta.runtime.spi.ConnectivitySnapshot;
import network.crypta.runtime.spi.ConnectivitySocketSnapshot;
import network.crypta.runtime.spi.ConnectivityTrafficEntrySnapshot;
import network.crypta.runtime.spi.ConnectivityTrafficInitiator;
import network.crypta.support.HTMLNode;
import network.crypta.support.TimeUtil;
import network.crypta.support.api.HTTPRequest;

/**
 * Toadlet that renders a human-readable dashboard about the node's current network connectivity.
 *
 * <p>The page is intended for operators who want to verify whether ports are reachable, how far
 * packets are traveling before receiving replies, and whether the node is exchanging traffic with
 * darknet peers or opennet introductions. The handler renders detached snapshots from {@link
 * ConnectivityPort}, keeping daemon-only connectivity trackers and alert implementations out of the
 * HTTP layer while preserving the current route and page structure.
 */
public class ConnectivityToadlet extends Toadlet {

  private static final String HTML_CLASS_ATTR = "class";
  private static final String TABLE_TAG = "table";
  private static final String EMPTY_HEADER_LABEL = " ";
  private static final String CONNECTIVITY_PORT_CLASS = "connectivity-port";
  private static final String CONNECTIVITY_IP_CLASS = "connectivity-ip";
  private static final int GAP_COLUMNS = 5;

  /**
   * Publicly visible path segment for registering the connectivity dashboard endpoint, including
   * leading and trailing slashes as expected by the toadlet router for consistent URL generation.
   */
  public static final String CONNECTIVITY_PATH = ConnectivityPagePaths.CONNECTIVITY_PATH;

  private record TrafficContext(String noreply, String local, String remote, long now) {}

  private final ConnectivityPort connectivity;

  /**
   * Creates a new connectivity toadlet bound to the given client and connectivity port.
   *
   * @param client high-level HTTP client used by the superclass for rendering utilities
   * @param connectivity read-only runtime connectivity port backing this page
   */
  protected ConnectivityToadlet(HighLevelSimpleClient client, ConnectivityPort connectivity) {
    super(client);
    this.connectivity = connectivity;
  }

  @Override
  public void handleMethodGET(URI uri, final HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    PageMaker pageMaker = ctx.getPageMaker();
    boolean includeAdvancedDetails = ctx.isAdvancedModeEnabled();
    ConnectivitySnapshot snapshot = connectivity.snapshot(includeAdvancedDetails);

    PageNode page =
        pageMaker.getPageNode(NodeL10n.getBase().getString("ConnectivityToadlet.title"), ctx);
    HTMLNode contentNode = page.getContentNode();

    addAlerts(ctx, contentNode);
    addPortInfobox(contentNode, snapshot);
    addConnectionTypeNotice(contentNode, pageMaker, snapshot.connectionTypeNotice());
    addSummary(contentNode, pageMaker, snapshot.sockets());

    if (includeAdvancedDetails) {
      addAdvancedDetails(contentNode, pageMaker, snapshot.sockets());
    }

    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private void addAlerts(ToadletContext ctx, HTMLNode contentNode) {
    if (ctx.isAllowedFullAccess()) {
      contentNode.addChild(ctx.getAlertManager().createSummary());
    }
  }

  private void addPortInfobox(HTMLNode contentNode, ConnectivitySnapshot snapshot) {
    HTMLNode portInfobox = contentNode.addChild("div", HTML_CLASS_ATTR, "infobox infobox-normal");
    portInfobox.addChild("div", HTML_CLASS_ATTR, "infobox-header", l10nConn("nodePortsTitle"));
    HTMLNode portInfoboxContent = portInfobox.addChild("div", HTML_CLASS_ATTR, "infobox-content");
    HTMLNode portInfoList = portInfoboxContent.addChild("ul");
    portInfoList.addChild(
        "li",
        NodeL10n.getBase()
            .getString(
                "DarknetConnectionsToadlet.darknetFnpPort",
                new String[] {"port"},
                new String[] {Integer.toString(snapshot.darknetFnpPort())}));
    if (snapshot.opennetFnpPort() > 0) {
      portInfoList.addChild(
          "li",
          NodeL10n.getBase()
              .getString(
                  "DarknetConnectionsToadlet.opennetFnpPort",
                  new String[] {"port"},
                  new String[] {Integer.toString(snapshot.opennetFnpPort())}));
    }
    addListenerPort(
        portInfoList,
        snapshot.fproxyListener(),
        "DarknetConnectionsToadlet.fproxyPort",
        l10nConn("fproxyDisabled"));
    addListenerPort(
        portInfoList,
        snapshot.fcpListener(),
        "DarknetConnectionsToadlet.fcpPort",
        l10nConn("fcpDisabled"));
    addListenerPort(
        portInfoList,
        snapshot.consoleListener(),
        "DarknetConnectionsToadlet.tmciPort",
        l10nConn("tmciDisabled"));
  }

  private void addListenerPort(
      HTMLNode portInfoList,
      ConnectivityListenerPortSnapshot listener,
      String l10nKey,
      String disabledLabel) {
    if (listener.enabled()) {
      portInfoList.addChild(
          "li",
          NodeL10n.getBase()
              .getString(
                  l10nKey,
                  new String[] {"port"},
                  new String[] {Integer.toString(listener.port())}));
      return;
    }
    portInfoList.addChild("li", disabledLabel);
  }

  private void addConnectionTypeNotice(
      HTMLNode contentNode, PageMaker pageMaker, ConnectivityNoticeSnapshot notice) {
    if (notice == null) {
      return;
    }
    if (!notice.renderedAlertHtml().isBlank()) {
      contentNode.addChild(new HTMLNode("%", notice.renderedAlertHtml()));
      return;
    }
    HTMLNode noticeContent =
        pageMaker.getInfobox("#", notice.title(), contentNode, "connectivity-notice", false);
    noticeContent.addChild("div", notice.text());
  }

  private void addSummary(
      HTMLNode contentNode, PageMaker pageMaker, List<ConnectivitySocketSnapshot> sockets) {
    HTMLNode summaryContent =
        pageMaker.getInfobox(
            "#",
            NodeL10n.getBase().getString("ConnectivityToadlet.summaryTitle"),
            contentNode,
            "connectivity-summary",
            true);

    HTMLNode table = summaryContent.addChild(TABLE_TAG, "border", "0");

    for (ConnectivitySocketSnapshot socket : sockets) {
      HTMLNode row = table.addChild("tr");
      row.addChild("td", socket.title());
      row.addChild("td", statusString(socket.portForwardStatus()));
    }
  }

  private void addAdvancedDetails(
      HTMLNode contentNode, PageMaker pageMaker, List<ConnectivitySocketSnapshot> sockets) {
    TrafficContext trafficContext =
        new TrafficContext(
            localize("noreply"), localize("local"), localize("remote"), System.currentTimeMillis());

    for (ConnectivitySocketSnapshot socket : sockets) {
      addPeerSection(contentNode, pageMaker, socket, trafficContext);
      addIpSection(contentNode, pageMaker, socket, trafficContext);
    }
  }

  private void addPeerSection(
      HTMLNode contentNode,
      PageMaker pageMaker,
      ConnectivitySocketSnapshot socket,
      TrafficContext trafficContext) {
    HTMLNode portsContent =
        pageMaker.getInfobox(
            "#",
            NodeL10n.getBase()
                .getString(
                    "ConnectivityToadlet.byPortTitle",
                    new String[] {"port", "status", "tunnelLength"},
                    new String[] {
                      socket.title(),
                      statusString(socket.portForwardStatus()),
                      TimeUtil.formatTime(socket.longestSendReceiveGapMillis())
                    }),
            contentNode,
            CONNECTIVITY_PORT_CLASS,
            false);
    HTMLNode table = portsContent.addChild(TABLE_TAG);
    addHeaderRow(table);
    for (ConnectivityTrafficEntrySnapshot entry : socket.peerEntries()) {
      addTrackerRow(
          table,
          entry,
          trafficContext.noreply,
          trafficContext.local,
          trafficContext.remote,
          trafficContext.now);
    }
  }

  private void addIpSection(
      HTMLNode contentNode,
      PageMaker pageMaker,
      ConnectivitySocketSnapshot socket,
      TrafficContext trafficContext) {
    HTMLNode portsContent =
        pageMaker.getInfobox(
            "#",
            NodeL10n.getBase()
                .getString(
                    "ConnectivityToadlet.byIPTitle",
                    new String[] {"ip", "status", "tunnelLength"},
                    new String[] {
                      socket.title(),
                      statusString(socket.portForwardStatus()),
                      TimeUtil.formatTime(socket.longestSendReceiveGapMillis())
                    }),
            contentNode,
            CONNECTIVITY_IP_CLASS,
            false);
    HTMLNode table = portsContent.addChild(TABLE_TAG);
    addHeaderRow(table);
    for (ConnectivityTrafficEntrySnapshot entry : socket.ipEntries()) {
      addTrackerRow(
          table,
          entry,
          trafficContext.noreply,
          trafficContext.local,
          trafficContext.remote,
          trafficContext.now);
    }
  }

  private void addHeaderRow(HTMLNode table) {
    HTMLNode row = table.addChild("tr");
    row.addChild("th", localize("addressTitle"));
    row.addChild("th", localize("sentReceivedTitle"));
    row.addChild("th", localize("localRemoteTitle"));
    row.addChild("th", localize("firstSendLeadTime"));
    row.addChild("th", localize("firstReceiveLeadTime"));
    for (int i = 0; i < GAP_COLUMNS; i++) {
      row.addChild("th", EMPTY_HEADER_LABEL);
    }
  }

  private void addTrackerRow(
      HTMLNode table,
      ConnectivityTrafficEntrySnapshot entry,
      String noreply,
      String local,
      String remote,
      long now) {
    HTMLNode row = table.addChild("tr");
    row.addChild("td", entry.address());
    row.addChild("td", entry.packetsSent() + "/ " + entry.packetsReceived());
    row.addChild("td", initiatorLabel(entry.initiator(), noreply, local, remote));
    row.addChild("td", TimeUtil.formatTime(entry.firstSendLeadTimeMillis()));
    row.addChild("td", TimeUtil.formatTime(entry.firstReceiveLeadTimeMillis()));
    List<ConnectivityGapSnapshot> gaps = entry.gaps();
    for (int i = 0; i < GAP_COLUMNS; i++) {
      String gap = i < gaps.size() ? gapLabel(gaps.get(i), now) : "";
      row.addChild("td", gap);
    }
  }

  private String initiatorLabel(
      ConnectivityTrafficInitiator initiator, String noreply, String local, String remote) {
    return switch (initiator) {
      case NO_REPLY -> noreply;
      case LOCAL -> local;
      case REMOTE -> remote;
    };
  }

  private String gapLabel(ConnectivityGapSnapshot gap, long now) {
    if (gap.receivedPacketAtMillis() == 0) {
      return "";
    }
    return TimeUtil.formatTime(gap.gapLengthMillis())
        + " @ "
        + TimeUtil.formatTime(now - gap.receivedPacketAtMillis())
        + " ago";
  }

  private String l10nConn(String string) {
    return NodeL10n.getBase().getString("DarknetConnectionsToadlet." + string);
  }

  private String localize(String key) {
    return NodeL10n.getBase().getString("ConnectivityToadlet." + key);
  }

  private String statusString(ConnectivityPortForwardStatus status) {
    return NodeL10n.getBase().getString("ConnectivityToadlet.status." + status);
  }

  @Override
  public String path() {
    return CONNECTIVITY_PATH;
  }
}

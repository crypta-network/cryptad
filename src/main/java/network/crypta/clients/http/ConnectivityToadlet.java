package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.io.AddressTracker;
import network.crypta.io.AddressTrackerItem;
import network.crypta.io.AddressTrackerItem.Gap;
import network.crypta.io.InetAddressAddressTrackerItem;
import network.crypta.io.PeerAddressTrackerItem;
import network.crypta.io.comm.UdpSocketHandler;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.FSParseException;
import network.crypta.node.Node;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;
import network.crypta.support.api.HTTPRequest;

/**
 * Toadlet that renders a human-readable dashboard about the node's current network connectivity. It
 * surfaces live data gathered by {@link AddressTracker} instances backing each UDP socket handler
 * and formats it into tables and infoboxes that are consumable through the web console.
 *
 * <p>The page is intended for operators who want to verify whether ports are reachable, how far
 * packets are travelling before receiving replies, and whether the node is exchanging traffic with
 * darknet peers or opennet introductions. The handler uses the {@link PageMaker} to assemble
 * localized sections covering port configuration, connectivity summaries, and per-peer or per-IP
 * traffic histories. When advanced mode is enabled it expands the page with gap timing breakdowns
 * and initiator information so administrators can diagnose asymmetric paths or stalled peers.
 *
 * <p>Instances are lightweight and stateless beyond a reference to the {@link Node}; they query the
 * node each time a request is processed, ensuring the view reflects the most recent tracker
 * readings. All rendering occurs on the request thread; no mutable state is shared across requests,
 * making the class thread-safe as long as the injected {@code Node} and client remain thread-safe.
 * Typical usage registers the toadlet on the web interface under {@link #CONNECTIVITY_PATH} so that
 * authenticated users can inspect connectivity without restarting the node.
 *
 * <ul>
 *   <li>Shows port enablement and configured bindings for HTTP, FCP, and console interfaces.
 *   <li>Displays port-forwarding status for each UDP socket handler with localized summaries.
 *   <li>Provides advanced per-peer and per-address gap timelines when advanced mode is requested.
 * </ul>
 *
 * @author toad
 * @see AddressTracker
 * @see network.crypta.clients.http.DarknetConnectionsToadlet
 */
public class ConnectivityToadlet extends Toadlet {

  private static final String HTML_CLASS_ATTR = "class";
  private static final String ENABLED_KEY = "enabled";
  private static final String TABLE_TAG = "table";
  private static final String EMPTY_HEADER_LABEL = " ";
  private static final String CONNECTIVITY_PORT_CLASS = "connectivity-port";
  private static final String CONNECTIVITY_IP_CLASS = "connectivity-ip";
  private static final String PATH_DELIMITER = "/";

  /**
   * Publicly visible path segment for registering the connectivity dashboard endpoint, including
   * leading and trailing slashes as expected by the toadlet router for consistent URL generation.
   */
  public static final String CONNECTIVITY_PATH =
      String.join(PATH_DELIMITER, "", "connectivity", "");

  private record TrafficContext(String noreply, String local, String remote, long now) {}

  private final Node node;

  /**
   * Creates a new connectivity toadlet bound to the given client and node.
   *
   * <p>The constructor keeps only lightweight references; all connectivity data is fetched lazily
   * during each request. Callers are expected to register the instance with the hosting web
   * interface under {@link #CONNECTIVITY_PATH} so authenticated visitors can access the dashboard.
   *
   * @param client high-level HTTP client used by the superclass for rendering utilities; must not
   *     be {@code null}.
   * @param node node whose address trackers and configuration are rendered on incoming requests; it
   *     should remain alive for the lifetime of this toadlet.
   */
  protected ConnectivityToadlet(HighLevelSimpleClient client, Node node) {
    super(client);
    this.node = node;
  }

  /**
   * Handles HTTP GET requests by rendering the connectivity dashboard for the current node state.
   *
   * <p>The method constructs infobox sections describing port configuration, port-forwarding
   * summaries for each UDP socket handler, and optionally advanced per-peer and per-address tables
   * when advanced mode is enabled in the {@link ToadletContext}. All content is localized through
   * {@link NodeL10n} and written as an HTML response without mutating node state. The call is
   * idempotent and safe to repeat for periodic status polling.
   *
   * @param uri request URI; only the path is used for rendering context and localization.
   * @param request parsed HTTP request containing parameters and authentication context; never
   *     modified by this method.
   * @param ctx toadlet execution context providing page builders and permission checks; must be
   *     open and authorized for the caller.
   * @throws ToadletContextClosedException if the client disconnects before the response is fully
   *     written or the context is otherwise closed mid-render.
   * @throws IOException if HTML generation or writing to the response stream fails for transport
   *     reasons such as socket errors.
   */
  public void handleMethodGET(URI uri, final HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    PageMaker pageMaker = ctx.getPageMaker();

    PageNode page =
        pageMaker.getPageNode(NodeL10n.getBase().getString("ConnectivityToadlet.title"), ctx);
    HTMLNode contentNode = page.getContentNode();

    addAlerts(ctx, contentNode);
    addPortInfobox(contentNode);

    node.network().ipDetector().addConnectionTypeBox(contentNode);

    UdpSocketHandler[] handlers = node.network().packetSocketHandlers();

    addSummary(contentNode, pageMaker, handlers);

    if (ctx.isAdvancedModeEnabled()) {
      addAdvancedDetails(contentNode, pageMaker, handlers);
    }

    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private void addAlerts(ToadletContext ctx, HTMLNode contentNode) {
    if (ctx.isAllowedFullAccess()) {
      contentNode.addChild(ctx.getAlertManager().createSummary());
    }
  }

  private void addPortInfobox(HTMLNode contentNode) {
    HTMLNode portInfobox = contentNode.addChild("div", HTML_CLASS_ATTR, "infobox infobox-normal");
    portInfobox.addChild("div", HTML_CLASS_ATTR, "infobox-header", l10nConn("nodePortsTitle"));
    HTMLNode portInfoboxContent = portInfobox.addChild("div", HTML_CLASS_ATTR, "infobox-content");
    HTMLNode portInfoList = portInfoboxContent.addChild("ul");
    SimpleFieldSet fproxyConfig = exportConfigSubset("fproxy");
    SimpleFieldSet fcpConfig = exportConfigSubset("fcp");
    SimpleFieldSet tmciConfig = exportConfigSubset("console");
    portInfoList.addChild(
        "li",
        NodeL10n.getBase()
            .getString(
                "DarknetConnectionsToadlet.darknetFnpPort",
                new String[] {"port"},
                new String[] {Integer.toString(node.network().fnpPort())}));
    int opennetPort = node.network().opennetFnpPort();
    if (opennetPort > 0) {
      portInfoList.addChild(
          "li",
          NodeL10n.getBase()
              .getString(
                  "DarknetConnectionsToadlet.opennetFnpPort",
                  new String[] {"port"},
                  new String[] {Integer.toString(opennetPort)}));
    }
    try {
      addPortConfigLine(
          portInfoList,
          fproxyConfig,
          "DarknetConnectionsToadlet.fproxyPort",
          l10nConn("fproxyDisabled"));
      addPortConfigLine(
          portInfoList, fcpConfig, "DarknetConnectionsToadlet.fcpPort", l10nConn("fcpDisabled"));
      addPortConfigLine(
          portInfoList, tmciConfig, "DarknetConnectionsToadlet.tmciPort", l10nConn("tmciDisabled"));
    } catch (FSParseException _) {
      // Ignore malformed config so the page still renders.
    }
  }

  private SimpleFieldSet exportConfigSubset(String subsetName) {
    return node.getConfig().get(subsetName).exportFieldSet(true);
  }

  private void addPortConfigLine(
      HTMLNode portInfoList, SimpleFieldSet config, String l10nKey, String disabledLabel)
      throws FSParseException {
    if (config.getBoolean(ENABLED_KEY, false)) {
      portInfoList.addChild(
          "li",
          NodeL10n.getBase()
              .getString(
                  l10nKey,
                  new String[] {"port"},
                  new String[] {Integer.toString(config.getInt("port"))}));
      return;
    }
    portInfoList.addChild("li", disabledLabel);
  }

  private void addSummary(HTMLNode contentNode, PageMaker pageMaker, UdpSocketHandler[] handlers) {
    HTMLNode summaryContent =
        pageMaker.getInfobox(
            "#",
            NodeL10n.getBase().getString("ConnectivityToadlet.summaryTitle"),
            contentNode,
            "connectivity-summary",
            true);

    HTMLNode table = summaryContent.addChild(TABLE_TAG, "border", "0");

    for (UdpSocketHandler handler : handlers) {
      AddressTracker tracker = handler.getAddressTracker();
      HTMLNode row = table.addChild("tr");
      row.addChild("td", handler.getTitle());
      row.addChild("td", AddressTracker.statusString(tracker.getPortForwardStatus()));
    }
  }

  private void addAdvancedDetails(
      HTMLNode contentNode, PageMaker pageMaker, UdpSocketHandler[] handlers) {
    TrafficContext trafficContext =
        new TrafficContext(
            localize("noreply"), localize("local"), localize("remote"), System.currentTimeMillis());

    for (UdpSocketHandler handler : handlers) {
      AddressTracker tracker = handler.getAddressTracker();
      addPeerSection(contentNode, pageMaker, handler, tracker, trafficContext);
      addIpSection(contentNode, pageMaker, handler, tracker, trafficContext);
    }
  }

  private void addPeerSection(
      HTMLNode contentNode,
      PageMaker pageMaker,
      UdpSocketHandler handler,
      AddressTracker tracker,
      TrafficContext trafficContext) {
    HTMLNode portsContent =
        pageMaker.getInfobox(
            "#",
            NodeL10n.getBase()
                .getString(
                    "ConnectivityToadlet.byPortTitle",
                    new String[] {"port", "status", "tunnelLength"},
                    new String[] {
                      handler.getTitle(),
                      AddressTracker.statusString(tracker.getPortForwardStatus()),
                      TimeUtil.formatTime(tracker.getLongestSendReceiveGap())
                    }),
            contentNode,
            CONNECTIVITY_PORT_CLASS,
            false);
    PeerAddressTrackerItem[] items = tracker.getPeerAddressTrackerItems();
    HTMLNode table = portsContent.addChild(TABLE_TAG);
    addHeaderRow(table);
    for (PeerAddressTrackerItem item : items) {
      addTrackerRow(
          table,
          item,
          item.peer.toString(),
          trafficContext.noreply,
          trafficContext.local,
          trafficContext.remote,
          trafficContext.now);
    }
  }

  private void addIpSection(
      HTMLNode contentNode,
      PageMaker pageMaker,
      UdpSocketHandler handler,
      AddressTracker tracker,
      TrafficContext trafficContext) {
    HTMLNode portsContent =
        pageMaker.getInfobox(
            "#",
            NodeL10n.getBase()
                .getString(
                    "ConnectivityToadlet.byIPTitle",
                    new String[] {"ip", "status", "tunnelLength"},
                    new String[] {
                      handler.getTitle(),
                      AddressTracker.statusString(tracker.getPortForwardStatus()),
                      TimeUtil.formatTime(tracker.getLongestSendReceiveGap())
                    }),
            contentNode,
            CONNECTIVITY_IP_CLASS,
            false);
    InetAddressAddressTrackerItem[] ipItems = tracker.getInetAddressTrackerItems();
    HTMLNode table = portsContent.addChild(TABLE_TAG);
    addHeaderRow(table);
    for (InetAddressAddressTrackerItem item : ipItems) {
      addTrackerRow(
          table,
          item,
          item.addr.toString(),
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
    for (int j = 0; j < AddressTrackerItem.TRACK_GAPS; j++) {
      row.addChild("th", EMPTY_HEADER_LABEL);
    }
  }

  private void addTrackerRow(
      HTMLNode table,
      AddressTrackerItem item,
      String address,
      String noreply,
      String local,
      String remote,
      long now) {
    HTMLNode row = table.addChild("tr");
    row.addChild("td", address);
    row.addChild("td", item.packetsSent() + "/ " + item.packetsReceived());
    row.addChild("td", initiatorLabel(item, noreply, local, remote));
    row.addChild("td", TimeUtil.formatTime(item.timeFromStartupToFirstSentPacket()));
    row.addChild("td", TimeUtil.formatTime(item.timeFromStartupToFirstReceivedPacket()));
    Gap[] gaps = item.getGaps();
    for (int k = 0; k < AddressTrackerItem.TRACK_GAPS; k++) {
      row.addChild("td", gapLabel(gaps[k], now));
    }
  }

  private String initiatorLabel(
      AddressTrackerItem item, String noreply, String local, String remote) {
    if (item.packetsReceived() == 0) {
      return noreply;
    }
    return item.weSentFirst() ? local : remote;
  }

  private String gapLabel(Gap gap, long now) {
    if (gap.receivedPacketAt() == 0) {
      return "";
    }
    return TimeUtil.formatTime(gap.gapLength())
        + " @ "
        + TimeUtil.formatTime(now - gap.receivedPacketAt())
        + " ago";
  }

  private String l10nConn(String string) {
    return NodeL10n.getBase().getString("DarknetConnectionsToadlet." + string);
  }

  private String localize(String key) {
    return NodeL10n.getBase().getString("ConnectivityToadlet." + key);
  }

  /**
   * Returns the HTTP path under which this toadlet should be registered.
   *
   * <p>The path is returned with leading and trailing slashes to match the routing expectations of
   * the hosting web server. It does not perform access checks; registration code should ensure only
   * authenticated callers reach {@link #handleMethodGET(URI, HTTPRequest, ToadletContext)}.
   *
   * @return {@code "/connectivity/"} for routing the connectivity status page within the web
   *     console.
   */
  @Override
  public String path() {
    return CONNECTIVITY_PATH;
  }
}

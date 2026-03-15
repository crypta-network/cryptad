package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.util.Objects;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.config.SubConfig;
import network.crypta.io.xfer.BlockReceiver;
import network.crypta.io.xfer.BlockTransmitter;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.OpennetManager;
import network.crypta.node.PeerStatusCounts;
import network.crypta.node.RequestTracker;
import network.crypta.runtime.spi.StatisticsPageSnapshot;
import network.crypta.runtime.spi.StatisticsPort;
import network.crypta.support.BandwidthStatsContainer;
import network.crypta.support.HTMLNode;
import network.crypta.support.SizeUtil;
import network.crypta.support.api.HTTPRequest;

/**
 * Serves the legacy statistics area at {@code /stats/} using detached runtime snapshots.
 *
 * <p>The request handler is intentionally thin. It performs access checks, dispatches between the
 * overview and requester routes, requests one detached statistics-page snapshot from {@link
 * StatisticsPort}, and injects the request-context-only fragments that still require a live {@link
 * ToadletContext} such as alert summaries and the wrapper-backed thread-dump form.
 *
 * <p>The legacy static helper methods used by {@link ConnectionsToadlet} remain here unchanged for
 * now. They are intentionally out of scope for this slice.
 */
public class StatisticsToadlet extends Toadlet {

  private static final String PATH_DELIMITER = "/";
  private static final String ATTR_CLASS = "class";
  private static final String ATTR_STYLE = "style";
  private static final String TITLE_ATTR = "title";
  private static final String CLASS_INFOBOX = "infobox";
  private static final String CLASS_INFOBOX_HEADER = "infobox-header";
  private static final String CLASS_INFOBOX_CONTENT = "infobox-content";
  private static final String CLASS_CONNECTED = "connected";
  private static final String PEER_LISTENING_CLASS = "peer_listening";
  private static final String PEER_LISTEN_ONLY_CLASS = "peer_listen_only";
  private static final String HOVER_STYLE = "border-bottom: 1px dotted; cursor: help;";
  private static final String STATS_PREFIX = "StatisticsToadlet.";
  private static final String TOTAL_KEY = "total";
  private static final String PERCENT_KEY = "percent";
  private static final String NBSP = "\u00a0";
  private static final String COLON_NBSP = ":" + NBSP;
  private static final String ALERT_SUMMARY_PLACEHOLDER = "<!--CRYPTA_ALERT_SUMMARY-->";
  private static final String STAT_GATHERING_BOX_PLACEHOLDER = "<!--CRYPTA_STAT_GATHERING_BOX-->";

  public static final String TOADLET_URL = String.join(PATH_DELIMITER, "", "stats", "");

  private final String path;
  private final StatisticsPort statistics;

  protected StatisticsToadlet(HighLevelSimpleClient client, StatisticsPort statistics) {
    this(client, statistics, TOADLET_URL);
  }

  StatisticsToadlet(HighLevelSimpleClient client, StatisticsPort statistics, String path) {
    super(client);
    this.path = Objects.requireNonNull(path);
    this.statistics = statistics;
  }

  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (!ctx.checkFullAccess(this)) {
      return;
    }

    String requestPath = request.getPath().substring(path().length());
    if (isRequestersPath(requestPath)) {
      renderPage(ctx, statistics.requesters().contentHtmlTemplate());
      return;
    }

    StatisticsPageSnapshot snapshot = statistics.overview(ctx.isAdvancedModeEnabled());
    renderPage(ctx, injectOverviewPlaceholders(snapshot, ctx));
  }

  private boolean isRequestersPath(String requestPath) {
    return !requestPath.isEmpty()
        && (requestPath.equals("requesters.html") || requestPath.equals("/requesters.html"));
  }

  private void renderPage(ToadletContext ctx, String contentHtml)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10n("fullTitle"), ctx);
    page.getContentNode().addChild("%", contentHtml);
    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private String injectOverviewPlaceholders(StatisticsPageSnapshot snapshot, ToadletContext ctx) {
    return snapshot
        .contentHtmlTemplate()
        .replace(ALERT_SUMMARY_PLACEHOLDER, renderAlertSummary(ctx))
        .replace(STAT_GATHERING_BOX_PLACEHOLDER, renderStatGatheringBox(snapshot, ctx));
  }

  private String renderAlertSummary(ToadletContext ctx) {
    if (!ctx.isAllowedFullAccess()) {
      return "";
    }
    return ctx.getAlertManager().createSummary().generate();
  }

  private String renderStatGatheringBox(StatisticsPageSnapshot snapshot, ToadletContext ctx) {
    HTMLNode statGatheringInfobox = new HTMLNode("div", ATTR_CLASS, CLASS_INFOBOX);
    statGatheringInfobox.addChild(
        "div", ATTR_CLASS, CLASS_INFOBOX_HEADER, l10n("statisticGatheringTitle"));
    HTMLNode statGatheringContent =
        statGatheringInfobox.addChild("div", ATTR_CLASS, CLASS_INFOBOX_CONTENT);

    if (snapshot.wrapperEnabled()) {
      HTMLNode threadDumpForm = ctx.addFormChild(statGatheringContent, "/", "threadDumpForm");
      threadDumpForm.addChild(
          "input",
          new String[] {"type", "name", "value"},
          new String[] {"submit", "getThreadDump", l10n("threadDumpButton")});
    }

    HTMLNode logsList = statGatheringContent.addChild("ul");
    if (snapshot.latestLogsEnabled()) {
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

    return statGatheringInfobox.generate();
  }

  @Override
  public String path() {
    return path;
  }

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

  static void drawBandwidth(HTMLNode activityList, Node node, long nodeUptimeSeconds) {
    long[] total = node.network().collector().getTotalIO();
    if (total[0] == 0 || total[1] == 0) {
      return;
    }
    long totalOutputRate = total[0] / nodeUptimeSeconds;
    long totalInputRate = total[1] / nodeUptimeSeconds;
    long totalPayload = node.getTotalPayloadSent();
    long totalPayloadRate = totalPayload / nodeUptimeSeconds;
    if (node.services().clientCore() == null) {
      throw new NullPointerException();
    }
    BandwidthStatsContainer stats =
        node.services()
            .clientCore()
            .getClientLayerPersister()
            .getBandwidthStatsPutter()
            .getLatestBWData();
    if (stats == null) {
      throw new NullPointerException();
    }
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
        "li", l10n("swapOutput", SizeUtil.formatSize(totalBytesSentSwapOutput, true)));
    activityList.addChild("li", l10n("authBytes", SizeUtil.formatSize(totalBytesSentAuth, true)));
    activityList.addChild(
        "li", l10n("ackOnlyBytes", SizeUtil.formatSize(totalBytesSentAckOnly, true)));
    activityList.addChild(
        "li",
        l10n(
            "resendBytes",
            new String[] {TOTAL_KEY, PERCENT_KEY},
            new String[] {
              SizeUtil.formatSize(totalBytesSentResends, true),
              Long.toString((100 * totalBytesSentResends) / Math.max(1, total[0]))
            }));
    activityList.addChild("li", l10n("uomBytes", SizeUtil.formatSize(totalBytesSentUOM, true)));
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
        "li", l10n("nodeToNodeBytes", SizeUtil.formatSize(totalBytesSentNodeToNode, true)));
    activityList.addChild(
        "li",
        l10n(
            "loadAllocationNoticesBytes",
            SizeUtil.formatSize(totalBytesSentAllocationNotices, true)));
    activityList.addChild("li", l10n("foafBytes", SizeUtil.formatSize(totalBytesSentFOAF, true)));
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
    }

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

  private static String l10n(String key) {
    return NodeL10n.getBase().getString(STATS_PREFIX + key);
  }

  private static String l10nDark(String key) {
    return NodeL10n.getBase().getString("DarknetConnectionsToadlet." + key);
  }

  private static String l10n(String key, String total) {
    return NodeL10n.getBase()
        .getString(STATS_PREFIX + key, new String[] {TOTAL_KEY}, new String[] {total});
  }

  private static String l10n(String key, String[] patterns, String[] values) {
    return NodeL10n.getBase().getString(STATS_PREFIX + key, patterns, values);
  }
}

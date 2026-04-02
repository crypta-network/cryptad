package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.util.Objects;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.spi.StatisticsPageSnapshot;
import network.crypta.runtime.spi.StatisticsPort;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;

/**
 * Serves the legacy statistics area at {@code /stats/} using detached runtime snapshots.
 *
 * <p>The request handler is intentionally thin. It performs access checks, dispatches between the
 * overview and requester routes, requests one detached statistics-page snapshot from {@link
 * StatisticsPort}, and injects the request-context-only fragments that still require a live {@link
 * ToadletContext} such as alert summaries and the wrapper-backed thread-dump form.
 *
 * <p>Only the detached `/stats/` request handler lives here now. The older live-node rendering
 * helpers were removed from this boundary-cleanup slice because they are owned by the legacy
 * statistics runtime adapter instead.
 */
public class StatisticsToadlet extends Toadlet {

  private static final String PATH_DELIMITER = "/";
  private static final String ATTR_CLASS = "class";
  private static final String CLASS_INFOBOX = "infobox";
  private static final String CLASS_INFOBOX_HEADER = "infobox-header";
  private static final String CLASS_INFOBOX_CONTENT = "infobox-content";
  private static final String STATS_PREFIX = "StatisticsToadlet.";
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

  private static String l10n(String key) {
    return NodeL10n.getBase().getString(STATS_PREFIX + key);
  }
}

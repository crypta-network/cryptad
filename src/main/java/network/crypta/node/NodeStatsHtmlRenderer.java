package network.crypta.node;

import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import network.crypta.io.xfer.BulkTransmitter;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.RequestTracker.WaitingForSlots;
import network.crypta.support.HTMLNode;
import network.crypta.support.TimeUtil;
import network.crypta.support.math.RunningAverage;

/**
 * Renders {@link NodeStats} metrics into HTML views.
 *
 * <p>Splitting this renderer out keeps {@link NodeStats} focused on data collection while isolating
 * UI formatting concerns.
 */
public final class NodeStatsHtmlRenderer {
  private static final String HTML_TABLE = "table";
  private static final String HTML_BORDER = "border";

  private NodeStatsHtmlRenderer() {}

  /**
   * Renders high-level success-rate statistics into the given HTML container.
   *
   * @param stats data source for metrics.
   * @param parent container node to append a table to; must not be {@code null}.
   */
  public static void fillSuccessRateBox(NodeStats stats, HTMLNode parent) {
    HTMLNode list = parent.addChild(HTML_TABLE, HTML_BORDER, "0");
    final RunningAverage[] averages =
        new RunningAverage[] {
          stats.globalFetchPSuccess,
          stats.chkLocalFetchPSuccess,
          stats.chkRemoteFetchPSuccess,
          stats.sskLocalFetchPSuccess,
          stats.sskRemoteFetchPSuccess,
          stats.blockTransferPSuccessBulk,
          stats.blockTransferPSuccessRT,
          stats.blockTransferPSuccessLocal,
          stats.blockTransferFailTimeout
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
    DecimalFormat fix3p3pct = new DecimalFormat("##0.000%");
    NumberFormat thousandPoint = NumberFormat.getInstance();
    addSuccessRateHeaderRow(stats, list);
    addSuccessRateRows(list, averages, names, fix3p3pct, thousandPoint);

    long[] bulkSuccess = BulkTransmitter.transferSuccess();
    HTMLNode row = list.addChild("tr");
    row.addChild("td", l10n("bulkSends"));
    row.addChild("td", fix3p3pct.format(((double) bulkSuccess[1]) / ((double) bulkSuccess[0])));
    row.addChild("td", Long.toString(bulkSuccess[0]));
  }

  private static void addSuccessRateHeaderRow(NodeStats stats, HTMLNode list) {
    HTMLNode row = list.addChild("tr");
    row.addChild("th", l10n("group"));
    row.addChild("th", l10n("pSuccess"));
    row.addChild("th", l10n("count"));
  }

  private static void addSuccessRateRows(
      HTMLNode list,
      RunningAverage[] averages,
      String[] names,
      DecimalFormat fix3p3pct,
      NumberFormat thousandPoint) {
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

  /**
   * Appends rows describing remote preemptive-reject reasons.
   *
   * @param stats data source for reject counters.
   * @param table an HTML table node to append rows to; must not be {@code null}.
   * @return {@code true} if any rows were added.
   */
  public static boolean getRejectReasonsTable(NodeStats stats, HTMLNode table) {
    return addRejectReasonRows(stats.preemptiveRejectReasons, table) > 0;
  }

  /**
   * Appends rows describing local preemptive-reject reasons.
   *
   * @param stats data source for reject counters.
   * @param table an HTML table node to append rows to; must not be {@code null}.
   * @return {@code true} if any rows were added.
   */
  public static boolean getLocalRejectReasonsTable(NodeStats stats, HTMLNode table) {
    return addRejectReasonRows(stats.localPreemptiveRejectReasons, table) > 0;
  }

  private static int addRejectReasonRows(Map<String, Integer> counts, HTMLNode table) {
    if (counts.isEmpty()) return 0;
    List<Map.Entry<String, Integer>> items = new ArrayList<>(counts.entrySet());
    items.sort(
        (a, b) -> {
          int cmp = Integer.compare(b.getValue(), a.getValue());
          if (cmp != 0) return cmp;
          String aKey = a.getKey();
          String bKey = b.getKey();
          if (aKey == null && bKey == null) return 0;
          if (aKey == null) return 1;
          if (bKey == null) return -1;
          return bKey.compareTo(aKey);
        });
    for (Map.Entry<String, Integer> entry : items) {
      HTMLNode row = table.addChild("tr");
      row.addChild("td", entry.getValue() + "\u00a0");
      row.addChild("td", entry.getKey());
    }
    return items.size();
  }

  public static void fillDetailedTimingsBox(NodeStats stats, HTMLNode html) {
    HTMLNode table = html.addChild(HTML_TABLE);
    HTMLNode row = table.addChild("tr");
    row.addChild("td");
    row.addChild("td", "colspan", "2", "CHK");
    row.addChild("td", "colspan", "2", "SSK");
    row = table.addChild("tr");
    row.addChild("td", l10n("successfulHeader"));
    row.addChild(
        "td",
        TimeUtil.formatTime(
            (long) stats.successfulLocalCHKFetchTimeAverageBulk.currentValue(), 2, true));
    row.addChild(
        "td",
        TimeUtil.formatTime(
            (long) stats.successfulLocalCHKFetchTimeAverageRT.currentValue(), 2, true));
    row.addChild(
        "td",
        TimeUtil.formatTime(
            (long) stats.successfulLocalSSKFetchTimeAverageBulk.currentValue(), 2, true));
    row.addChild(
        "td",
        TimeUtil.formatTime(
            (long) stats.successfulLocalSSKFetchTimeAverageRT.currentValue(), 2, true));
    row = table.addChild("tr");
    row.addChild("td", l10n("unsuccessfulHeader"));
    row.addChild(
        "td",
        TimeUtil.formatTime(
            (long) stats.unsuccessfulLocalCHKFetchTimeAverageBulk.currentValue(), 2, true));
    row.addChild(
        "td",
        TimeUtil.formatTime(
            (long) stats.unsuccessfulLocalCHKFetchTimeAverageRT.currentValue(), 2, true));
    row.addChild(
        "td",
        TimeUtil.formatTime(
            (long) stats.unsuccessfulLocalSSKFetchTimeAverageBulk.currentValue(), 2, true));
    row.addChild(
        "td",
        TimeUtil.formatTime(
            (long) stats.unsuccessfulLocalSSKFetchTimeAverageRT.currentValue(), 2, true));
    row = table.addChild("tr");
    row.addChild("td", l10n("averageHeader"));
    row.addChild(
        "td",
        TimeUtil.formatTime((long) stats.localCHKFetchTimeAverageBulk.currentValue(), 2, true));
    row.addChild(
        "td", TimeUtil.formatTime((long) stats.localCHKFetchTimeAverageRT.currentValue(), 2, true));
    row.addChild(
        "td",
        TimeUtil.formatTime((long) stats.localSSKFetchTimeAverageBulk.currentValue(), 2, true));
    row.addChild(
        "td", TimeUtil.formatTime((long) stats.localSSKFetchTimeAverageRT.currentValue(), 2, true));
  }

  /** Renders NLM delay and timeout fractions to HTML. */
  public static void drawNewLoadManagementDelayTimes(NodeStats stats, HTMLNode content) {
    WaitingForSlots waitingSlots = stats.node.getTracker().countRequestsWaitingForSlots();
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
    double[] delayValues = stats.getNlmDelaySnapshot();
    row.addChild("td", TimeUtil.formatTime((int) delayValues[0], 2, true));
    row.addChild("td", TimeUtil.formatTime((int) delayValues[1], 2, true));
    row = table.addChild("tr");
    row.addChild("th", l10n("bulkHeader"));
    row.addChild("td", TimeUtil.formatTime((int) delayValues[2], 2, true));
    row.addChild("td", TimeUtil.formatTime((int) delayValues[3], 2, true));

    long[] slotTimeouts = stats.getSlotTimeoutSnapshot();
    long fatalTimeoutsInWaitLocal = slotTimeouts[0];
    long fatalTimeoutsInWaitRemote = slotTimeouts[1];
    long allocatedSlotLocal = slotTimeouts[2];
    long allocatedSlotRemote = slotTimeouts[3];
    if (fatalTimeoutsInWaitLocal
            + fatalTimeoutsInWaitRemote
            + allocatedSlotLocal
            + allocatedSlotRemote
        > 0) {
      DecimalFormat fix3p3pct = new DecimalFormat("##0.000%");
      content.addChild("b", l10n("timeoutFractions"));
      table = content.addChild(HTML_TABLE, HTML_BORDER, "0");
      header = table.addChild("tr");
      header.addChild("th", l10n("localHeader"));
      header.addChild("th", l10n("remoteHeader"));
      row = table.addChild("tr");
      row.addChild(
          "td",
          fix3p3pct.format(
              ((double) fatalTimeoutsInWaitLocal)
                  / ((double) (fatalTimeoutsInWaitLocal + allocatedSlotLocal))));
      row.addChild(
          "td",
          fix3p3pct.format(
              ((double) fatalTimeoutsInWaitRemote)
                  / ((double) (fatalTimeoutsInWaitRemote + allocatedSlotRemote))));
    }
  }

  public static void fillRemoteRequestHTLsBox(NodeStats stats, HTMLNode html, boolean realTime) {
    stats.getHourlyStats(realTime).fillRemoteRequestHTLsBox(html);
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("NodeStats." + key);
  }

  private static String l10n(String key, String[] patterns, String[] values) {
    return NodeL10n.getBase().getString("NodeStats." + key, patterns, values);
  }
}

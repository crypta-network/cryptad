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
 * <p>This utility converts live node statistics into human-readable tables and paragraphs for
 * status pages. Callers supply a {@link NodeStats} instance plus an {@link HTMLNode} container, and
 * each method appends structured rows instead of returning a standalone document. The renderer
 * keeps no state and performs only formatting; it reflects whatever snapshot values are exposed by
 * {@code NodeStats} at call time, so repeated calls will show updated counters and averages.
 *
 * <p>Thread-safety follows the inputs: the class itself is stateless, but callers should avoid
 * mutating the same {@link HTMLNode} from multiple threads and should ensure the supplied {@link
 * NodeStats} supports concurrent reads.
 *
 * <ul>
 *   <li>Responsibility: format rates, timing averages, and per-reason counts.
 *   <li>Output: tables and paragraphs appended to an existing HTML tree.
 *   <li>No side effects beyond HTML node construction.
 * </ul>
 *
 * @see NodeStats
 * @see HTMLNode
 */
public final class NodeStatsHtmlRenderer {
  private static final String HTML_TABLE = "table";
  private static final String HTML_BORDER = "border";

  private NodeStatsHtmlRenderer() {}

  /**
   * Renders high-level success-rate statistics into the given HTML container.
   *
   * <p>The method appends a table that summarizes overall request success rates, per-key-type
   * rates, and transfer outcomes. Each {@link RunningAverage} is rendered as a percentage with
   * three decimal places and a formatted count; if an average has no reports, the table shows a
   * dash and zero. A final row reports bulk transfer success based on {@link BulkTransmitter}
   * counters. The call is not idempotent: invoking it multiple times will append multiple tables.
   *
   * @param stats data source providing running averages and counters; must be non-null.
   * @param parent container node that receives a new table child.
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
    addSuccessRateHeaderRow(list);
    addSuccessRateRows(list, averages, names, fix3p3pct, thousandPoint);

    long[] bulkSuccess = BulkTransmitter.transferSuccess();
    HTMLNode row = list.addChild("tr");
    row.addChild("td", l10n("bulkSends"));
    row.addChild("td", fix3p3pct.format(((double) bulkSuccess[1]) / ((double) bulkSuccess[0])));
    row.addChild("td", Long.toString(bulkSuccess[0]));
  }

  private static void addSuccessRateHeaderRow(HTMLNode list) {
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
   * <p>The rows are derived from the current reject counters and are appended to the provided table
   * in descending count order, with a stable alphabetical tie-breaker. This method does not clear
   * or replace existing table content, so callers typically create or position the table header
   * before invoking it. The call has no effect when no reject reasons are recorded.
   *
   * @param stats data source providing reject counters; must be non-null.
   * @param table HTML table node that receives new reject rows.
   * @return {@code true} when at least one reject-reason row is appended.
   */
  public static boolean getRejectReasonsTable(NodeStats stats, HTMLNode table) {
    return addRejectReasonRows(stats.preemptiveRejectReasons, table) > 0;
  }

  /**
   * Appends rows describing local preemptive-reject reasons.
   *
   * <p>The rows are derived from the current local reject counters and are appended to the provided
   * table in descending count order, with a stable alphabetical tie-breaker. The method does not
   * clear or replace existing content, so callers should add headers up front. If no local rejects
   * are present, the table is left unchanged.
   *
   * @param stats data source providing reject counters; must be non-null.
   * @param table HTML table node that receives new reject rows.
   * @return {@code true} when at least one reject-reason row is appended.
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

  /**
   * Appends a detailed timing table for CHK/SSK local fetch durations.
   *
   * <p>The table includes separate columns for CHK and SSK timings and rows for successful,
   * unsuccessful, and overall averages. Values are formatted as human-readable durations using
   * {@link TimeUtil}, based on the current running averages held in {@code stats}. Each call
   * appends a fresh table to the supplied container; repeated calls will create multiple tables
   * rather than updating existing ones.
   *
   * @param stats data source providing timing averages; must be non-null.
   * @param html container node that receives the timing table.
   */
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

  /**
   * Renders NLM delay and timeout fractions to HTML.
   *
   * <p>The method adds a brief paragraph describing how many requests are waiting for slots, then
   * renders a table of delay snapshots for real-time and bulk traffic, split into local and remote
   * columns. When slot timeout counts are available, an additional table is appended that expresses
   * fatal timeouts as fractions of allocated slots. All values are derived from snapshot methods on
   * {@code stats} and are formatted for display; no state is cached.
   *
   * @param stats data source providing delay snapshots and slot counters.
   * @param content container node that receives paragraphs and tables.
   */
  public static void drawNewLoadManagementDelayTimes(NodeStats stats, HTMLNode content) {
    WaitingForSlots waitingSlots = stats.node.routing().tracker().countRequestsWaitingForSlots();
    content
        .addChild("p")
        .addChild(
            "#",
            NodeL10n.getBase()
                .getString(
                    "NodeStats.slotsWaiting",
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

  /**
   * Appends the remote-request HTL summary for the selected traffic class.
   *
   * <p>This method delegates to the hourly statistics view, selecting either real-time or bulk
   * counters based on {@code realTime}. The delegate writes its output into the provided HTML
   * container, so callers should pass an initialized node and manage any surrounding headers. The
   * call is additive and does not clear or reuse prior content.
   *
   * @param stats data source providing hourly statistics; must be non-null.
   * @param html container node that receives the HTL summary.
   * @param realTime {@code true} for real-time traffic, {@code false} for bulk.
   */
  public static void fillRemoteRequestHTLsBox(NodeStats stats, HTMLNode html, boolean realTime) {
    stats.getHourlyStats(realTime).fillRemoteRequestHTLsBox(html);
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("NodeStats." + key);
  }
}

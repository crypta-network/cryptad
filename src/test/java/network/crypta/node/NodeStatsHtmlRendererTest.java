package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import network.crypta.node.RequestTracker.WaitingForSlots;
import network.crypta.support.HTMLNode;
import network.crypta.support.TimeUtil;
import network.crypta.support.math.TrivialRunningAverage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeStatsHtmlRendererTest {
  private static final String HTML_TABLE = "table";
  private static final String TABLE_OPEN_TAG = "<" + HTML_TABLE;

  @Test
  void fillSuccessRateBox_whenAveragesHaveData_formatsCountsAndPercentages() {
    NodeStats stats = mock(NodeStats.class);
    TrivialRunningAverage reported = averageWithReport(0.5);
    setField(stats, "globalFetchPSuccess", reported);
    setField(stats, "chkLocalFetchPSuccess", new TrivialRunningAverage());
    setField(stats, "chkRemoteFetchPSuccess", new TrivialRunningAverage());
    setField(stats, "sskLocalFetchPSuccess", new TrivialRunningAverage());
    setField(stats, "sskRemoteFetchPSuccess", new TrivialRunningAverage());
    setField(stats, "blockTransferPSuccessBulk", new TrivialRunningAverage());
    setField(stats, "blockTransferPSuccessRT", new TrivialRunningAverage());
    setField(stats, "blockTransferPSuccessLocal", new TrivialRunningAverage());
    setField(stats, "blockTransferFailTimeout", new TrivialRunningAverage());

    HTMLNode parent = new HTMLNode("div");

    NodeStatsHtmlRenderer.fillSuccessRateBox(stats, parent);

    List<List<String>> rows = extractTableCells(parent.getChildren().getFirst());
    assertEquals(11, rows.size());

    DecimalFormat pctFormat = new DecimalFormat("##0.000%");
    NumberFormat countFormat = NumberFormat.getInstance();
    String expectedPercent = pctFormat.format(reported.currentValue());
    String expectedCount = countFormat.format(reported.countReports());

    assertTrue(
        rows.stream()
            .anyMatch(cells -> cells.contains(expectedPercent) && cells.contains(expectedCount)),
        "Expected a row with the reported percentage and count");
    assertTrue(
        rows.stream().anyMatch(cells -> cells.contains("-") && cells.contains("0")),
        "Expected at least one row for a zero-count average");
  }

  @Test
  void fillSuccessRateBox_whenParentNull_throwsNullPointerException() {
    NodeStats stats = mock(NodeStats.class);

    //noinspection DataFlowIssue
    assertThrows(
        NullPointerException.class, () -> NodeStatsHtmlRenderer.fillSuccessRateBox(stats, null));
  }

  @Test
  void getRejectReasonsTable_whenCountsEmpty_returnsFalseAndNoRows() {
    NodeStats stats = mock(NodeStats.class);
    setField(stats, "preemptiveRejectReasons", new HashMap<>());
    HTMLNode table = new HTMLNode(HTML_TABLE);

    boolean result = NodeStatsHtmlRenderer.getRejectReasonsTable(stats, table);

    assertFalse(result);
    assertEquals(0, table.getChildren().size());
  }

  @Test
  void getRejectReasonsTable_whenCountsPresent_sortsAndRendersRows() {
    NodeStats stats = mock(NodeStats.class);
    Map<String, Integer> counts = new HashMap<>();
    counts.put("alpha", 5);
    counts.put("beta", 5);
    counts.put("gamma", 3);
    counts.put(null, 5);
    setField(stats, "preemptiveRejectReasons", counts);
    HTMLNode table = new HTMLNode(HTML_TABLE);

    boolean result = NodeStatsHtmlRenderer.getRejectReasonsTable(stats, table);

    assertTrue(result);
    List<List<String>> rows = extractTableCells(table);
    assertEquals(4, rows.size());
    assertRejectRow(rows.get(0), 5, "beta");
    assertRejectRow(rows.get(1), 5, "alpha");
    assertRejectRow(rows.get(2), 5, "");
    assertRejectRow(rows.get(3), 3, "gamma");
  }

  @Test
  void getLocalRejectReasonsTable_whenCountsPresent_sortsAndRendersRows() {
    NodeStats stats = mock(NodeStats.class);
    Map<String, Integer> counts = new HashMap<>();
    counts.put("local-low", 1);
    counts.put("local-high", 10);
    setField(stats, "localPreemptiveRejectReasons", counts);
    HTMLNode table = new HTMLNode(HTML_TABLE);

    boolean result = NodeStatsHtmlRenderer.getLocalRejectReasonsTable(stats, table);

    assertTrue(result);
    List<List<String>> rows = extractTableCells(table);
    assertEquals(2, rows.size());
    assertRejectRow(rows.get(0), 10, "local-high");
    assertRejectRow(rows.get(1), 1, "local-low");
  }

  @Test
  void fillDetailedTimingsBox_whenAveragesPresent_rendersFormattedTimes() {
    NodeStats stats = mock(NodeStats.class);
    setField(stats, "successfulLocalCHKFetchTimeAverageBulk", averageWithReport(1100));
    setField(stats, "successfulLocalCHKFetchTimeAverageRT", averageWithReport(2200));
    setField(stats, "successfulLocalSSKFetchTimeAverageBulk", averageWithReport(3300));
    setField(stats, "successfulLocalSSKFetchTimeAverageRT", averageWithReport(4400));
    setField(stats, "unsuccessfulLocalCHKFetchTimeAverageBulk", averageWithReport(5500));
    setField(stats, "unsuccessfulLocalCHKFetchTimeAverageRT", averageWithReport(6600));
    setField(stats, "unsuccessfulLocalSSKFetchTimeAverageBulk", averageWithReport(7700));
    setField(stats, "unsuccessfulLocalSSKFetchTimeAverageRT", averageWithReport(8800));
    setField(stats, "localCHKFetchTimeAverageBulk", averageWithReport(9900));
    setField(stats, "localCHKFetchTimeAverageRT", averageWithReport(11100));
    setField(stats, "localSSKFetchTimeAverageBulk", averageWithReport(12200));
    setField(stats, "localSSKFetchTimeAverageRT", averageWithReport(13300));

    HTMLNode html = new HTMLNode("div");

    NodeStatsHtmlRenderer.fillDetailedTimingsBox(stats, html);

    String output = html.generate();
    assertTrue(output.contains(TimeUtil.formatTime(1100, 2, true)));
    assertTrue(output.contains(TimeUtil.formatTime(2200, 2, true)));
    assertTrue(output.contains(TimeUtil.formatTime(3300, 2, true)));
    assertTrue(output.contains(TimeUtil.formatTime(4400, 2, true)));
    assertTrue(output.contains(TimeUtil.formatTime(5500, 2, true)));
    assertTrue(output.contains(TimeUtil.formatTime(6600, 2, true)));
    assertTrue(output.contains(TimeUtil.formatTime(7700, 2, true)));
    assertTrue(output.contains(TimeUtil.formatTime(8800, 2, true)));
    assertTrue(output.contains(TimeUtil.formatTime(9900, 2, true)));
    assertTrue(output.contains(TimeUtil.formatTime(11100, 2, true)));
    assertTrue(output.contains(TimeUtil.formatTime(12200, 2, true)));
    assertTrue(output.contains(TimeUtil.formatTime(13300, 2, true)));
  }

  @Test
  void drawNewLoadManagementDelayTimes_whenTimeoutsPresent_rendersTimeoutTable() {
    NodeStats stats = mock(NodeStats.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    RequestTracker tracker = mock(RequestTracker.class);
    WaitingForSlots waiting = new WaitingForSlots();
    waiting.local = 2;
    waiting.remote = 4;
    when(tracker.countRequestsWaitingForSlots()).thenReturn(waiting);
    when(node.routing().tracker()).thenReturn(tracker);
    setField(stats, "node", node);
    when(stats.getNlmDelaySnapshot()).thenReturn(new double[] {1000, 2000, 3000, 4000});
    when(stats.getSlotTimeoutSnapshot()).thenReturn(new long[] {1, 3, 9, 7});

    HTMLNode content = new HTMLNode("div");

    NodeStatsHtmlRenderer.drawNewLoadManagementDelayTimes(stats, content);

    String output = content.generate();
    assertTrue(output.contains(TimeUtil.formatTime(1000, 2, true)));
    assertTrue(output.contains(TimeUtil.formatTime(2000, 2, true)));
    assertTrue(output.contains(TimeUtil.formatTime(3000, 2, true)));
    assertTrue(output.contains(TimeUtil.formatTime(4000, 2, true)));

    DecimalFormat pctFormat = new DecimalFormat("##0.000%");
    String expectedLocal = pctFormat.format(1.0 / (1 + 9));
    String expectedRemote = pctFormat.format(3.0 / (3 + 7));
    assertTrue(output.contains(expectedLocal));
    assertTrue(output.contains(expectedRemote));
    assertEquals(2, countTableOpenTags(output));
  }

  @Test
  void drawNewLoadManagementDelayTimes_whenNoTimeouts_skipsTimeoutTable() {
    NodeStats stats = mock(NodeStats.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    RequestTracker tracker = mock(RequestTracker.class);
    WaitingForSlots waiting = new WaitingForSlots();
    waiting.local = 0;
    waiting.remote = 0;
    when(tracker.countRequestsWaitingForSlots()).thenReturn(waiting);
    when(node.routing().tracker()).thenReturn(tracker);
    setField(stats, "node", node);
    when(stats.getNlmDelaySnapshot()).thenReturn(new double[] {500, 600, 700, 800});
    when(stats.getSlotTimeoutSnapshot()).thenReturn(new long[] {0, 0, 0, 0});

    HTMLNode content = new HTMLNode("div");

    NodeStatsHtmlRenderer.drawNewLoadManagementDelayTimes(stats, content);

    String output = content.generate();
    assertTrue(output.contains(TimeUtil.formatTime(500, 2, true)));
    assertEquals(1, countTableOpenTags(output));
  }

  @Test
  void fillRemoteRequestHTLsBox_whenCalled_delegatesToHourlyStats() {
    NodeStats stats = mock(NodeStats.class);
    HourlyStats hourlyStats = mock(HourlyStats.class);
    HTMLNode html = new HTMLNode("div");
    when(stats.getHourlyStats(true)).thenReturn(hourlyStats);

    NodeStatsHtmlRenderer.fillRemoteRequestHTLsBox(stats, html, true);

    verify(stats).getHourlyStats(true);
    verify(hourlyStats).fillRemoteRequestHTLsBox(html);
  }

  private static TrivialRunningAverage averageWithReport(double value) {
    TrivialRunningAverage average = new TrivialRunningAverage();
    average.report(value);
    return average;
  }

  @SuppressWarnings("java:S3011")
  private static void setField(NodeStats stats, String fieldName, Object value) {
    try {
      Field field = NodeStats.class.getDeclaredField(fieldName);
      field.setAccessible(true);
      field.set(stats, value);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("Failed to set field " + fieldName, e);
    }
  }

  private static List<List<String>> extractTableCells(HTMLNode table) {
    List<List<String>> rows = new ArrayList<>();
    for (HTMLNode row : table.getChildren()) {
      List<String> cells = new ArrayList<>();
      for (HTMLNode cell : row.getChildren()) {
        cells.add(cell.generateChildren().trim());
      }
      rows.add(cells);
    }
    return rows;
  }

  private static void assertRejectRow(List<String> cells, int expectedCount, String expectedKey) {
    assertEquals(2, cells.size());
    assertEquals(Integer.toString(expectedCount), digitsOnly(cells.get(0)));
    assertEquals(expectedKey, cells.get(1));
  }

  private static String digitsOnly(String value) {
    return value.replaceAll("\\D", "");
  }

  private static int countTableOpenTags(String input) {
    int count = 0;
    int index = 0;
    while ((index = input.indexOf(TABLE_OPEN_TAG, index)) >= 0) {
      count++;
      index += TABLE_OPEN_TAG.length();
    }
    return count;
  }
}

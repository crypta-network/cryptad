package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import network.crypta.support.HTMLNode;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class HourlyStatsRecordTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @BeforeEach
  void setUp() {
    when(node.maxHTL()).thenReturn((short) 10);
    Mockito.lenient().when(node.network().location()).thenReturn(0.5);
    Mockito.lenient().when(node.network().uptimeEstimator().getUptime()).thenReturn(42_000d);
  }

  @Test
  void constructor_andToString_emitExpectedSectionCounts() {
    // Arrange
    when(node.maxHTL()).thenReturn((short) 4); // smaller for deterministic counting
    HourlyStatsRecord rec = new HourlyStatsRecord(node, false);

    // Act
    String txt = rec.toString();

    // Assert: one HTL row per index 0..max inclusive, and 16 distance buckets
    assertEquals(5, countOccurrences(txt, "HourlyStats: HTL\t"), "HTL rows");
    assertEquals(16, countOccurrences(txt, "HourlyStats: logDist\t"), "distance rows");
    // The toString() flags were renamed to tab-separated keys: "completeHour" and "finished".
    assertTrue(
        txt.contains("completeHour\tfalse\tfinished\tfalse"), "flags present with updated labels");
  }

  @Test
  void markFinal_thenAnyRemoteRequest_throwsIllegalState() {
    // Arrange
    HourlyStatsRecord rec = new HourlyStatsRecord(node, true);
    rec.markFinal();

    // Act + Assert
    assertThrows(
        IllegalStateException.class,
        () -> rec.remoteRequest(false, true, true, 1, 0.25),
        "modifying a finalized record must fail");
  }

  @Test
  void remoteRequest_withInvalidArguments_throws() {
    // Arrange
    HourlyStatsRecord rec = new HourlyStatsRecord(node, false);

    // Act + Assert: negative HTL
    assertThrows(
        IllegalArgumentException.class, () -> rec.remoteRequest(false, true, true, -1, 0.3));

    // Act + Assert: location out of [0,1]
    assertThrows(
        IllegalArgumentException.class, () -> rec.remoteRequest(false, true, true, 0, -0.01));
    assertThrows(
        IllegalArgumentException.class, () -> rec.remoteRequest(true, false, false, 0, 1.01));
  }

  @Test
  void remoteRequest_htlClampedToMax_andCountsRecordedByHtlAndDist() {
    // Arrange
    HourlyStatsRecord rec = new HourlyStatsRecord(node, false);

    // Act: HTL above max should clamp to maxHTL() = 10; distance 0.25 -> bucket 2
    rec.remoteRequest(false, true, true, 10_000, 0.75);

    // Assert: HTL line for 10 gets CHK local success = 1; others 0
    int[] htl10 = parseSixCountsForLine(rec.toString(), "HourlyStats: HTL\t10\t");
    assertArrayEquals(new int[] {1, 0, 0, 0, 0, 0}, htl10, "HTL counters after clamp");

    // Assert: logDist bucket 2 reflects the same single CHK local success
    int[] dist2 = parseSixCountsForLine(rec.toString(), "HourlyStats: logDist\t2\t");
    assertArrayEquals(new int[] {1, 0, 0, 0, 0, 0}, dist2, "distance bucket counters");
  }

  @Test
  void remoteRequest_recordsAllOutcomeCounters_atSameHtlAndBucket() {
    // Arrange
    HourlyStatsRecord rec = getHourlyStatsRecord();

    // Assert: HTL 4 shows 1 in each of the six counters
    int[] htl4 = parseSixCountsForLine(rec.toString(), "HourlyStats: HTL\t4\t");
    assertArrayEquals(new int[] {1, 1, 1, 1, 1, 1}, htl4, "HTL counters must reflect six events");

    // Assert: bucket 2 also shows 1 in each of the six counters
    int[] dist2 = parseSixCountsForLine(rec.toString(), "HourlyStats: logDist\t2\t");
    assertArrayEquals(
        new int[] {1, 1, 1, 1, 1, 1}, dist2, "distance counters must reflect six events");
  }

  private @NotNull HourlyStatsRecord getHourlyStatsRecord() {
    HourlyStatsRecord rec = new HourlyStatsRecord(node, false);

    // Act: location 0.75 -> distance 0.25 -> bucket 2; use HTL 4
    rec.remoteRequest(false, true, true, 4, 0.75); // CHK local success
    rec.remoteRequest(false, true, false, 4, 0.75); // CHK remote success
    rec.remoteRequest(false, false, false, 4, 0.75); // CHK failure
    rec.remoteRequest(true, true, true, 4, 0.75); // SSK local success
    rec.remoteRequest(true, true, false, 4, 0.75); // SSK remote success
    rec.remoteRequest(true, false, false, 4, 0.75); // SSK failure
    return rec;
  }

  @Test
  void remoteRequest_zeroDistance_saturatesToLastBucket() {
    // Arrange
    HourlyStatsRecord rec = new HourlyStatsRecord(node, false);

    // Act: node location == request location -> zero raw distance -> uses Double.MIN_VALUE ->
    // bucket saturates to 15
    rec.remoteRequest(false, false, false, 2, 0.5); // CHK failure

    // Assert: HTL 2 gets a single CHK failure; bucket 15 as well
    int[] htl2 = parseSixCountsForLine(rec.toString(), "HourlyStats: HTL\t2\t");
    assertArrayEquals(new int[] {0, 0, 1, 0, 0, 0}, htl2, "HTL counters on failure");

    int[] dist15 = parseSixCountsForLine(rec.toString(), "HourlyStats: logDist\t15\t");
    assertArrayEquals(new int[] {0, 0, 1, 0, 0, 0}, dist15, "saturated distance bucket");
  }

  @Test
  void fillRemoteRequestHTLsBox_aggregatesTotalsAcrossHtls() {
    // Arrange
    when(node.maxHTL()).thenReturn((short) 5);
    String html = getHtml();

    // Assert: headers and expected totals present
    assertTrue(html.contains("<th>HTL</th>"), "includes HTL header");
    assertTrue(html.contains("<th>CHKs</th>"), "includes CHKs header");
    assertTrue(html.contains("<th>SSKs</th>"), "includes SSKs header");

    // Totals appear as "(LS,RS,T)"; we check for the exact triplets
    assertTrue(html.contains("(1,1,3)"), "CHK totals should be (1,1,3)");
    assertTrue(html.contains("(2,1,4)"), "SSK totals should be (2,1,4)");
  }

  private String getHtml() {
    HourlyStatsRecord rec = new HourlyStatsRecord(node, false);

    // Events: CHK -> (LS=1, RS=1, F=1) ; SSK -> (LS=2, RS=1, F=1)
    rec.remoteRequest(false, true, true, 2, 0.75); // CHK LS
    rec.remoteRequest(false, true, false, 2, 0.75); // CHK RS
    rec.remoteRequest(false, false, false, 3, 0.75); // CHK F

    rec.remoteRequest(true, true, true, 1, 0.75); // SSK LS
    rec.remoteRequest(true, true, true, 1, 0.75); // SSK LS
    rec.remoteRequest(true, true, false, 1, 0.75); // SSK RS
    rec.remoteRequest(true, false, false, 1, 0.75); // SSK F

    HTMLNode root = new HTMLNode("div");

    // Act
    rec.fillRemoteRequestHTLsBox(root);
    return root.generate();
  }

  // --- Helpers ---

  private static int countOccurrences(String haystack, String needle) {
    int count = 0;
    int idx = 0;
    while ((idx = haystack.indexOf(needle, idx)) >= 0) {
      count++;
      idx += needle.length();
    }
    return count;
  }

  private static final Pattern LINE_PATTERN = Pattern.compile("^(.+)$", Pattern.MULTILINE);

  private static int[] parseSixCountsForLine(String txt, String linePrefix) {
    Matcher m = LINE_PATTERN.matcher(txt);
    while (m.find()) {
      String line = m.group(1);
      if (line.startsWith(linePrefix)) {
        String tail = line.substring(linePrefix.length());
        StringTokenizer tokenizer = new StringTokenizer(tail, "\t");
        String[] tokens = new String[tokenizer.countTokens()];
        for (int tokenIndex = 0; tokenizer.hasMoreTokens(); tokenIndex++) {
          tokens[tokenIndex] = tokenizer.nextToken();
        }
        // First six tokens are the counts from StatsLine.toString()
        return new int[] {
          parseIntSafe(tokens[0]),
          parseIntSafe(tokens[1]),
          parseIntSafe(tokens[2]),
          parseIntSafe(tokens[3]),
          parseIntSafe(tokens[4]),
          parseIntSafe(tokens[5])
        };
      }
    }
    throw new AssertionError("Line not found: " + linePrefix + " in\n" + txt);
  }

  private static int parseIntSafe(String s) {
    return Integer.parseInt(s.trim());
  }
}

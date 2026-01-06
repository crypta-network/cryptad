package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class HourlyStatsTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @BeforeEach
  void setUp() {
    when(node.maxHTL()).thenReturn((short) 10);
  }

  @Test
  void remoteRequest_withinSameHour_doesNotRotateAndForwards() throws Exception {
    // Arrange
    HourlyStats stats = new HourlyStats(node);
    when(node.network().location()).thenReturn(0.5);
    HourlyStatsRecord initialCurrent = getField(stats, "currentRecord", HourlyStatsRecord.class);

    // Act
    stats.remoteRequest(false, true, true, 3, 0.75);

    // Assert
    HourlyStatsRecord afterCurrent = getField(stats, "currentRecord", HourlyStatsRecord.class);
    HourlyStatsRecord prev = getField(stats, "prevRecord", HourlyStatsRecord.class);
    assertSame(
        initialCurrent, afterCurrent, "currentRecord should not be replaced within same hour");
    assertNull(prev, "prevRecord must stay null without an hour rollover");
  }

  @Test
  void remoteRequest_whenHourChanges_rotatesAndMarksPreviousFinal() throws Exception {
    // Arrange
    HourlyStats stats = new HourlyStats(node);
    HourlyStatsRecord beforeCurrent = getField(stats, "currentRecord", HourlyStatsRecord.class);

    // Force lastHourlyTime to a different UTC hour than 'now' to trigger rollover
    // deterministically.
    Calendar lastHourly = getField(stats, "lastHourlyTime", Calendar.class);
    Calendar nowUtc = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
    nowUtc.setTime(new Date());
    nowUtc.add(Calendar.HOUR_OF_DAY, -1);
    lastHourly.setTime(nowUtc.getTime());

    // Act: first request in the new hour triggers rotation
    when(node.network().location()).thenReturn(0.5);
    stats.remoteRequest(true, false, false, 2, 0.80);

    // Assert
    HourlyStatsRecord prev = getField(stats, "prevRecord", HourlyStatsRecord.class);
    HourlyStatsRecord current = getField(stats, "currentRecord", HourlyStatsRecord.class);
    assertNotNull(prev, "prevRecord should be set after hour rollover");
    assertTrue(getBooleanField(prev, "finishedReporting"), "previous record must be marked final");

    // The record that became previous is the old current, which was constructed with
    // completeHour=false
    assertFalse(
        getBooleanField(prev, "completeHour"),
        "previous record should not represent a complete hour");

    // A fresh current record should be created for the new hour with completeHour=true
    assertNotNull(current, "current record must exist after rotation");
    assertTrue(
        getBooleanField(current, "completeHour"), "new current must represent a complete hour");

    // And it must be a different instance than the old current.
    // (prev was the old current; current must be new)
    assertTrue(
        beforeCurrent == prev && current != beforeCurrent,
        "rotation must move old current to prev");
  }

  @Test
  void remoteRequest_withNegativeHtl_throwsIllegalArgument() {
    // Arrange
    HourlyStats stats = new HourlyStats(node);

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class, () -> stats.remoteRequest(false, true, true, -1, 0.5));
  }

  @Test
  void remoteRequest_withInvalidLocation_throwsIllegalArgument() {
    // Arrange
    HourlyStats stats = new HourlyStats(node);

    // Act + Assert: below 0 range
    assertThrows(
        IllegalArgumentException.class, () -> stats.remoteRequest(false, false, false, 1, -0.01));

    // Act + Assert: above 1 range
    assertThrows(
        IllegalArgumentException.class, () -> stats.remoteRequest(true, false, false, 1, 1.01));
  }

  @Test
  void fillRemoteRequestHTLsBox_buildsTableStructure() {
    // Arrange
    HourlyStats stats = new HourlyStats(node);
    HTMLNode root = new HTMLNode("div");

    // Act
    stats.fillRemoteRequestHTLsBox(root);

    // Assert: ensure table and expected headers are present in generated HTML
    String html = root.generate();
    assertTrue(html.contains("<table>"), "should contain a table");
    assertTrue(html.contains("<th>HTL</th>"), "should include HTL header");
    assertTrue(html.contains("<th>CHKs</th>"), "should include CHKs header");
    assertTrue(html.contains("<th>SSKs</th>"), "should include SSKs header");
    assertTrue(html.contains("Total"), "should include a Total row");
  }

  // --- Reflection helpers ---

  private static <T> T getField(Object target, String name, Class<T> type) throws Exception {
    Field f = target.getClass().getDeclaredField(name);
    f.setAccessible(true);
    return type.cast(f.get(target));
  }

  private static boolean getBooleanField(Object target, String name) throws Exception {
    Field f = target.getClass().getDeclaredField(name);
    f.setAccessible(true);
    return f.getBoolean(target);
  }
}

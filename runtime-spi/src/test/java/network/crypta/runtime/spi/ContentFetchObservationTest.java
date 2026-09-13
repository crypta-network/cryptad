package network.crypta.runtime.spi;

import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("java:S100")
class ContentFetchObservationTest {
  @Test
  void legacyFetchPortExplicitlyReportsUnsupportedObservation() {
    ContentFetchPort port = _ -> null;
    assertFalse(port.observation().known());
  }

  @Test
  void rejectsIllegalCountsAndInconsistentLifecycleTotals() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new ContentFetchObservation(true, "epoch", 1, 1, -1, 0, 0, 0, 0, false));
    assertThrows(
        IllegalArgumentException.class,
        () -> new ContentFetchObservation(true, "epoch", 1, 1, 1, 0, 0, 0, 0, false));
  }

  @Test
  void constructor_whenAnyCounterIsNegative_expectRejected() {
    for (int index = 0; index < 7; index++) {
      long[] counts = new long[7];
      counts[index] = -1;
      assertThrows(
          IllegalArgumentException.class,
          () ->
              new ContentFetchObservation(
                  false, "", counts[0], counts[1], counts[2], counts[3], counts[4], counts[5],
                  counts[6], true));
    }
  }

  @Test
  void constructor_whenEpochIsMissing_expectRejectedEvenForTruncatedSamples() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new ContentFetchObservation(false, null, 0, 0, 0, 0, 0, 0, 0, true));
    assertThrows(
        IllegalArgumentException.class,
        () -> new ContentFetchObservation(true, " ", 0, 0, 0, 0, 0, 0, 0, true));
  }

  @Test
  void constructor_whenCompletedCountsExceedStarted_expectRejectedWithoutOverflow() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new ContentFetchObservation(true, "epoch", 0, 0, 0, 0, 1, 2, 0, false));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new ContentFetchObservation(
                true, "epoch", 0, 0, 0, 0, Long.MAX_VALUE, Long.MAX_VALUE, 1, false));
  }

  @Test
  void constructor_whenTotalsAreUnavailableOrTruncated_expectNoLifecycleAssertion() {
    var unknown = new ContentFetchObservation(false, "", 0, 0, 2, 0, 0, 3, 4, false);
    var truncated = new ContentFetchObservation(true, "epoch", 0, 0, 2, 0, 0, 3, 4, true);
    var complete =
        new ContentFetchObservation(
            true, "epoch", 0, 0, 0, 0, Long.MAX_VALUE, Long.MAX_VALUE - 1, 1, false);

    assertFalse(unknown.known());
    assertTrue(truncated.truncated());
    assertEquals(Long.MAX_VALUE, complete.startedOperations());
  }

  @Test
  void fixedManagementReadsHaveNumericMetricsWithoutRawRuntimeInventory() {
    Map<String, Object> snapshot = JvmResourceObservation.capture();
    assertEquals("fixed-management-beans-v1", snapshot.get("collector"));
    Map<?, ?> metrics = (Map<?, ?>) snapshot.get("metrics");
    assertEquals(9, metrics.size());
    for (Object value : metrics.values()) {
      assertTrue(value == null || value instanceof Number);
      if (value instanceof Number number) assertTrue(number.longValue() >= 0);
    }
    assertTrue(
        ((Number) metrics.get("heapCommittedBytes")).longValue()
            >= ((Number) metrics.get("heapUsedBytes")).longValue());
    assertFalse(snapshot.containsKey("commandLine"));
  }
}

package network.crypta.clients.http.wizardsteps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import network.crypta.node.Node;
import network.crypta.support.io.DatastoreUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100"}) // test naming convention: method_whenCondition_expectOutcome
class BandwidthLimitTest {

  private static final long SECONDS_PER_MONTH = 2_592_000L;

  private static long bytesPerMonthFromBytesPerSecond(long bytesPerSecond) {
    return Math.multiplyExact(bytesPerSecond, SECONDS_PER_MONTH);
  }

  @Test
  @SuppressWarnings({"MisorderedAssertEqualsArguments", "java:S3415"})
  void constants_whenMinMonthlyLimitCalculated_expectMatchesFormula() {
    assertNotNull(BandwidthLimit.MIN_MONTHLY_LIMIT, "MIN_MONTHLY_LIMIT must be initialized");

    double expectedGiB =
        2 * Node.getMinimumBandwidth() * BandwidthLimit.SECONDS_PER_MONTH / DatastoreUtil.ONE_GIB;

    assertEquals(expectedGiB, BandwidthLimit.MIN_MONTHLY_LIMIT, 1e-12d);
    assertTrue(BandwidthLimit.MIN_MONTHLY_LIMIT > 0, "Minimum monthly limit should be positive");
  }

  @Test
  void constructor_whenExplicitValuesProvided_expectFieldsAssigned() {
    long down = 1_234L;
    long up = 5_678L;
    String key = "l10n.key";
    boolean maybeDefault = true;

    BandwidthLimit limit = new BandwidthLimit(down, up, key, maybeDefault);

    assertEquals(down, limit.downBytes);
    assertEquals(up, limit.upBytes);
    assertEquals(key, limit.descriptionKey);
    assertTrue(limit.maybeDefault);
  }

  @Test
  void constructor_whenDescriptionKeyNull_expectNullPreserved() {
    BandwidthLimit limit = new BandwidthLimit(1L, 2L, null, false);

    assertNull(limit.descriptionKey);
    assertFalse(limit.maybeDefault);
  }

  @Test
  void constructor_whenBytesPerMonthAtMinimum_expectUpAndDownAtMinimum() {
    int minBps = Node.getMinimumBandwidth();
    long bytesPerSecond = 2L * minBps;
    long bytesPerMonth = bytesPerMonthFromBytesPerSecond(bytesPerSecond);

    BandwidthLimit limit = new BandwidthLimit(bytesPerMonth);

    assertEquals(minBps, limit.downBytes);
    assertEquals(minBps, limit.upBytes);
    assertEquals("Monthly bandwidth limit", limit.descriptionKey);
    assertFalse(limit.maybeDefault);
  }

  @Test
  void constructor_whenBytesPerMonthAddsTenBytesPerSecond_expect80_20Split() {
    int minBps = Node.getMinimumBandwidth();
    long bytesPerSecond = 2L * minBps + 10L;
    long bytesPerMonth = bytesPerMonthFromBytesPerSecond(bytesPerSecond);

    BandwidthLimit limit = new BandwidthLimit(bytesPerMonth);

    assertEquals(minBps + 8L, limit.downBytes);
    assertEquals(minBps + 2L, limit.upBytes);
  }

  @Test
  void constructor_whenBytesPerMonthAddsOneBytePerSecond_expectCeilMakesLimitsEqual() {
    int minBps = Node.getMinimumBandwidth();
    long bytesPerSecond = 2L * minBps + 1L;
    long bytesPerMonth = bytesPerMonthFromBytesPerSecond(bytesPerSecond);

    BandwidthLimit limit = new BandwidthLimit(bytesPerMonth);

    assertEquals(minBps + 1L, limit.downBytes);
    assertEquals(minBps + 1L, limit.upBytes);
  }

  @ParameterizedTest
  @DisplayName("BandwidthLimit(bytesPerMonth): min+ -> down>=up and >= minimum")
  @ValueSource(longs = {0L, 1L, 2L, 10L, 123L, 999L})
  void constructor_whenBytesPerMonthAtOrAboveMinimum_expectDownAtLeastUpAndSumWithinCeilBounds(
      long extraBytesPerSecond) {
    int minBps = Node.getMinimumBandwidth();
    long bytesPerSecond = 2L * minBps + extraBytesPerSecond;
    long bytesPerMonth = bytesPerMonthFromBytesPerSecond(bytesPerSecond);

    BandwidthLimit limit = new BandwidthLimit(bytesPerMonth);

    assertTrue(limit.downBytes >= limit.upBytes, "Expected downBytes >= upBytes");
    assertTrue(limit.downBytes >= minBps, "Expected downBytes >= minimum");
    assertTrue(limit.upBytes >= minBps, "Expected upBytes >= minimum");

    long sum = limit.downBytes + limit.upBytes;
    assertTrue(sum >= bytesPerSecond, "Ceil should not under-allocate total bandwidth");
    assertTrue(sum < bytesPerSecond + 2L, "Ceil of two values should add < 2 bytes/sec overhead");
  }
}

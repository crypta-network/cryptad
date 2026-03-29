package network.crypta.clients.http.wizardsteps;

import network.crypta.support.io.DatastoreUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100"}) // test naming convention: method_whenCondition_expectOutcome
class BandwidthLimitTest {

  private static final long MIN_BYTES_PER_SECOND = 32L * 1024L;
  private static final long SECONDS_PER_MONTH = 2_592_000L;

  private static long bytesPerMonthFromBytesPerSecond(long bytesPerSecond) {
    return Math.multiplyExact(bytesPerSecond, SECONDS_PER_MONTH);
  }

  @Test
  @SuppressWarnings({"java:S3415"})
  void minimumMonthlyLimitGiB_whenCalculated_expectMatchesFormula() {
    double expectedGiB =
        2 * MIN_BYTES_PER_SECOND * WizardBandwidthLimit.SECONDS_PER_MONTH / DatastoreUtil.ONE_GIB;
    double minimumMonthlyLimitGiB =
        WizardBandwidthLimit.minimumMonthlyLimitGiB(MIN_BYTES_PER_SECOND);

    assertEquals(expectedGiB, minimumMonthlyLimitGiB, 1e-12d);
    assertTrue(minimumMonthlyLimitGiB > 0, "Minimum monthly limit should be positive");
  }

  @Test
  void constructor_whenExplicitValuesProvided_expectFieldsAssigned() {
    long down = 1_234L;
    long up = 5_678L;
    String key = "l10n.key";
    boolean maybeDefault = true;

    WizardBandwidthLimit limit = new WizardBandwidthLimit(down, up, key, maybeDefault);

    assertEquals(down, limit.downBytes());
    assertEquals(up, limit.upBytes());
    assertEquals(key, limit.descriptionKey());
    assertTrue(limit.maybeDefault());
  }

  @Test
  void constructor_whenDescriptionKeyNull_expectNullPreserved() {
    WizardBandwidthLimit limit = new WizardBandwidthLimit(1L, 2L, null, false);

    assertNull(limit.descriptionKey());
    assertFalse(limit.maybeDefault());
  }

  @Test
  void fromMonthlyBudget_whenBytesPerMonthAtMinimum_expectUpAndDownAtMinimum() {
    long bytesPerSecond = 2L * MIN_BYTES_PER_SECOND;
    long bytesPerMonth = bytesPerMonthFromBytesPerSecond(bytesPerSecond);

    WizardBandwidthLimit limit =
        WizardBandwidthLimit.fromMonthlyBudget(bytesPerMonth, MIN_BYTES_PER_SECOND);

    assertEquals(MIN_BYTES_PER_SECOND, limit.downBytes());
    assertEquals(MIN_BYTES_PER_SECOND, limit.upBytes());
    assertEquals("Monthly bandwidth limit", limit.descriptionKey());
    assertFalse(limit.maybeDefault());
  }

  @Test
  void fromMonthlyBudget_whenBytesPerMonthAddsTenBytesPerSecond_expect80_20Split() {
    long bytesPerSecond = 2L * MIN_BYTES_PER_SECOND + 10L;
    long bytesPerMonth = bytesPerMonthFromBytesPerSecond(bytesPerSecond);

    WizardBandwidthLimit limit =
        WizardBandwidthLimit.fromMonthlyBudget(bytesPerMonth, MIN_BYTES_PER_SECOND);

    assertEquals(MIN_BYTES_PER_SECOND + 8L, limit.downBytes());
    assertEquals(MIN_BYTES_PER_SECOND + 2L, limit.upBytes());
  }

  @Test
  void fromMonthlyBudget_whenBytesPerMonthAddsOneBytePerSecond_expectCeilMakesLimitsEqual() {
    long bytesPerSecond = 2L * MIN_BYTES_PER_SECOND + 1L;
    long bytesPerMonth = bytesPerMonthFromBytesPerSecond(bytesPerSecond);

    WizardBandwidthLimit limit =
        WizardBandwidthLimit.fromMonthlyBudget(bytesPerMonth, MIN_BYTES_PER_SECOND);

    assertEquals(MIN_BYTES_PER_SECOND + 1L, limit.downBytes());
    assertEquals(MIN_BYTES_PER_SECOND + 1L, limit.upBytes());
  }

  @ParameterizedTest
  @DisplayName(
      "WizardBandwidthLimit.fromMonthlyBudget(bytesPerMonth, min): min+ -> down>=up and >= minimum")
  @ValueSource(longs = {0L, 1L, 2L, 10L, 123L, 999L})
  void
      fromMonthlyBudget_whenBytesPerMonthAtOrAboveMinimum_expectDownAtLeastUpAndSumWithinCeilBounds(
          long extraBytesPerSecond) {
    long bytesPerSecond = 2L * MIN_BYTES_PER_SECOND + extraBytesPerSecond;
    long bytesPerMonth = bytesPerMonthFromBytesPerSecond(bytesPerSecond);

    WizardBandwidthLimit limit =
        WizardBandwidthLimit.fromMonthlyBudget(bytesPerMonth, MIN_BYTES_PER_SECOND);

    assertTrue(limit.downBytes() >= limit.upBytes(), "Expected downBytes >= upBytes");
    assertTrue(limit.downBytes() >= MIN_BYTES_PER_SECOND, "Expected downBytes >= minimum");
    assertTrue(limit.upBytes() >= MIN_BYTES_PER_SECOND, "Expected upBytes >= minimum");

    long sum = limit.downBytes() + limit.upBytes();
    assertTrue(sum >= bytesPerSecond, "Ceil should not under-allocate total bandwidth");
    assertTrue(sum < bytesPerSecond + 2L, "Ceil of two values should add < 2 bytes/sec overhead");
  }
}

package network.crypta.support;

import java.lang.reflect.Field;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.NANOSECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class OutputThrottleTest {
  private static final long ONE_SECOND_NANOS = SECONDS.toNanos(1);
  private static final String TIME_LAST_TICK_FIELD = "timeLastTick";

  @ParameterizedTest
  @ValueSource(longs = {0L, -1L})
  void constructor_whenNanosPerTickIsNotPositive_expectIllegalArgumentException(long nanosPerTick) {
    // Arrange + Act + Assert
    assertThrows(IllegalArgumentException.class, () -> new OutputThrottle(10L, nanosPerTick, 0L));
  }

  @ParameterizedTest
  @ValueSource(longs = {0L, -1L})
  void constructor_whenMaxTokensIsNotPositive_expectIllegalArgumentException(long maxTokens) {
    // Arrange + Act + Assert
    assertThrows(
        IllegalArgumentException.class, () -> new OutputThrottle(maxTokens, ONE_SECOND_NANOS, 0L));
  }

  @Test
  void constructor_whenInitialTokensExceedMax_expectCountClampedToMax() {
    // Arrange
    OutputThrottle throttle = new OutputThrottle(5L, ONE_SECOND_NANOS, 99L);

    // Act
    long count = throttle.getCount();

    // Assert
    assertEquals(5L, count);
  }

  @Test
  void getNanosPerTick_whenConstructed_expectConfiguredValue() {
    // Arrange
    long nanosPerTick = 42_000L;
    OutputThrottle throttle = new OutputThrottle(10L, nanosPerTick, 0L);

    // Act
    long actual = throttle.getNanosPerTick();

    // Assert
    assertEquals(nanosPerTick, actual);
  }

  @ParameterizedTest
  @ValueSource(longs = {0L, -1L})
  void changeNanosAndBucketSize_whenNanosPerTickIsNotPositive_expectIllegalArgumentException(
      long nanosPerTick) {
    // Arrange
    OutputThrottle throttle = new OutputThrottle(10L, ONE_SECOND_NANOS, 0L);

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class, () -> throttle.changeNanosAndBucketSize(nanosPerTick, 10L));
  }

  @ParameterizedTest
  @ValueSource(longs = {0L, -1L})
  void changeNanosAndBucketSize_whenNewMaxIsNotPositive_expectIllegalArgumentException(
      long newMaxTokens) {
    // Arrange
    OutputThrottle throttle = new OutputThrottle(10L, ONE_SECOND_NANOS, 0L);

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> throttle.changeNanosAndBucketSize(ONE_SECOND_NANOS, newMaxTokens));
  }

  @Test
  void changeNanosAndBucketSize_whenNewMaxBelowCurrent_expectCountClippedToNewMax() {
    // Arrange
    OutputThrottle throttle = new OutputThrottle(10L, ONE_SECOND_NANOS, 8L);

    // Act
    throttle.changeNanosAndBucketSize(ONE_SECOND_NANOS, 5L);

    // Assert
    assertEquals(5L, throttle.getCount());
  }

  @Test
  void changeNanosAndBucketSize_whenUpdated_expectNewNanosPerTickReported() {
    // Arrange
    OutputThrottle throttle = new OutputThrottle(10L, ONE_SECOND_NANOS, 1L);
    long newNanosPerTick = 250_000L;

    // Act
    throttle.changeNanosAndBucketSize(newNanosPerTick, 20L);

    // Assert
    assertEquals(newNanosPerTick, throttle.getNanosPerTick());
  }

  @Test
  void forceGrab_whenNegativeTokenCount_expectIllegalArgumentException() {
    // Arrange
    OutputThrottle throttle = new OutputThrottle(10L, ONE_SECOND_NANOS, 0L);

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> throttle.forceGrab(-1L));
  }

  @Test
  void forceGrab_whenMoreTokensThanCurrent_expectCountCanBecomeNegative() {
    // Arrange
    OutputThrottle throttle = new OutputThrottle(10L, ONE_SECOND_NANOS, 3L);

    // Act
    throttle.forceGrab(5L);

    // Assert
    assertEquals(-2L, throttle.getCount());
  }

  @Test
  void getCount_whenOneTickElapsed_expectSingleTokenAdded() {
    // Arrange
    OutputThrottle throttle = new OutputThrottle(10L, ONE_SECOND_NANOS, 0L);
    setTimeLastTick(throttle, nowNs() - ONE_SECOND_NANOS);

    // Act
    long count = throttle.getCount();

    // Assert
    assertEquals(1L, count);
  }

  @Test
  void getCount_whenMultipleTicksElapsed_expectMultipleTokensAdded() {
    // Arrange
    OutputThrottle throttle = new OutputThrottle(10L, ONE_SECOND_NANOS, 0L);
    setTimeLastTick(throttle, nowNs() - (4L * ONE_SECOND_NANOS));

    // Act
    long count = throttle.getCount();

    // Assert
    assertEquals(3L, count);
  }

  @Test
  void getCount_whenAccruedTokensExceedMax_expectCountClippedToMax() {
    // Arrange
    OutputThrottle throttle = new OutputThrottle(2L, ONE_SECOND_NANOS, 0L);
    setTimeLastTick(throttle, nowNs() - (10L * ONE_SECOND_NANOS));

    // Act
    long count = throttle.getCount();

    // Assert
    assertEquals(2L, count);
  }

  @Test
  void getCount_whenClockSkewDetected_expectCountUnchangedAndTimestampResynced() {
    // Arrange
    OutputThrottle throttle = new OutputThrottle(10L, ONE_SECOND_NANOS, 4L);
    setTimeLastTick(throttle, nowNs() + (2L * ONE_SECOND_NANOS));

    // Act
    long count = throttle.getCount();
    long updatedTimeLastTick = readTimeLastTick(throttle);

    // Assert
    assertEquals(4L, count);
    assertTrue(updatedTimeLastTick <= nowNs());
  }

  private static long nowNs() {
    long nowMs = System.currentTimeMillis();
    return NANOSECONDS.convert(nowMs, MILLISECONDS);
  }

  private static void setTimeLastTick(OutputThrottle throttle, long value) {
    setLongField(throttle, value);
  }

  private static long readTimeLastTick(OutputThrottle throttle) {
    return readLongField(throttle);
  }

  private static void setLongField(OutputThrottle throttle, long value) {
    try {
      Field field = OutputThrottle.class.getDeclaredField(TIME_LAST_TICK_FIELD);
      field.setAccessible(true);
      field.setLong(throttle, value);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("Failed to set test field: " + TIME_LAST_TICK_FIELD, e);
    }
  }

  private static long readLongField(OutputThrottle throttle) {
    try {
      Field field = OutputThrottle.class.getDeclaredField(TIME_LAST_TICK_FIELD);
      field.setAccessible(true);
      return field.getLong(throttle);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("Failed to read test field: " + TIME_LAST_TICK_FIELD, e);
    }
  }
}

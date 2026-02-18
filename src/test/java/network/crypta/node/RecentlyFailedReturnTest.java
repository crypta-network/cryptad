package network.crypta.node;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class RecentlyFailedReturnTest {

  @Test
  @DisplayName("recentlyFailed when never failed returns -1 sentinel")
  void recentlyFailed_whenNeverFailed_returnsMinusOne() {
    // Arrange
    RecentlyFailedReturn rfr = new RecentlyFailedReturn();

    // Act
    long result = rfr.recentlyFailed();

    // Assert
    assertEquals(-1L, result, "Expected sentinel -1 when no failure recorded");
  }

  @ParameterizedTest(name = "wakeup={0}")
  @org.junit.jupiter.params.provider.ValueSource(longs = {123456789L, 1L, 987654321L})
  @DisplayName("fail sets flag and exact wakeup")
  void fail_whenCalled_setsFlagAndWakeupExactly(long wakeup) {
    // Arrange
    RecentlyFailedReturn rfr = new RecentlyFailedReturn();

    // Act
    rfr.fail(wakeup);

    // Assert
    assertEquals(
        wakeup,
        rfr.recentlyFailed(),
        "recentlyFailed should return the exact wakeup value that was set");
  }

  @Test
  @DisplayName("fail called multiple times updates to latest wakeup")
  void fail_whenCalledMultipleTimes_updatesWakeupToLatest() {
    // Arrange
    RecentlyFailedReturn rfr = new RecentlyFailedReturn();
    long first = 100L;
    long second = 200L;

    // Act
    rfr.fail(first);
    long afterFirst = rfr.recentlyFailed();
    rfr.fail(second);
    long afterSecond = rfr.recentlyFailed();

    // Assert
    assertEquals(first, afterFirst, "Should return first wakeup after initial fail");
    assertEquals(second, afterSecond, "Should return latest wakeup after subsequent fail");
  }

  @Test
  @DisplayName("fail accepts negative wakeup and returns it when recently failed")
  void recentlyFailed_whenNegativeWakeup_returnsThatNegativeValue() {
    // Arrange
    RecentlyFailedReturn rfr = new RecentlyFailedReturn();
    long negativeWakeup = -42L;

    // Act
    rfr.fail(negativeWakeup);
    long value = rfr.recentlyFailed();

    // Assert
    assertEquals(
        negativeWakeup, value, "Should return the negative wakeup value that was set explicitly");
  }
}

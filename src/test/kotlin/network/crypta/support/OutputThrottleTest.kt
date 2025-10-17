package network.crypta.support

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource

/**
 * Tests for [OutputThrottle].
 *
 * Design notes for determinism:
 * - Uses a very large `nanosPerTick` so that no automatic token accrual happens during the test
 *   run.
 * - Avoids sleeping and time-based assertions.
 */
@Suppress("kotlin:S100")
class OutputThrottleTest {

  private val oneDayNanos: Long = 86_400_000_000_000L // 24h in nanoseconds

  @Test
  @DisplayName("getCount_whenConstructed_returnsInitialTokensWithoutTicking")
  fun getCount_whenConstructed_returnsInitialTokensWithoutTicking() {
    // Arrange
    val throttle = OutputThrottle(maxTokens = 100, nanosPerTick = oneDayNanos, initialTokens = 42)

    // Act
    val count = throttle.getCount()

    // Assert
    assertEquals(42, count)
  }

  @Test
  @DisplayName("forceGrab_whenEnoughTokens_decrementsBalance")
  fun forceGrab_whenEnoughTokens_decrementsBalance() {
    // Arrange
    val throttle = OutputThrottle(maxTokens = 100, nanosPerTick = oneDayNanos, initialTokens = 100)

    // Act
    throttle.forceGrab(10)
    val remaining = throttle.getCount()

    // Assert
    assertEquals(90, remaining)
  }

  @Test
  @DisplayName("forceGrab_whenInsufficientTokens_allowsNegativeBalance")
  fun forceGrab_whenInsufficientTokens_allowsNegativeBalance() {
    // Arrange
    val throttle = OutputThrottle(maxTokens = 100, nanosPerTick = oneDayNanos, initialTokens = 5)

    // Act
    throttle.forceGrab(10)
    val remaining = throttle.getCount()

    // Assert
    assertEquals(-5, remaining)
  }

  @Test
  @DisplayName("forceGrab_whenNegativeTokens_throws")
  fun forceGrab_whenNegativeTokens_throws() {
    // Arrange
    val throttle = OutputThrottle(maxTokens = 100, nanosPerTick = oneDayNanos, initialTokens = 50)

    // Act + Assert
    assertThrows(IllegalArgumentException::class.java) { throttle.forceGrab(-1) }
  }

  @Test
  @DisplayName("changeNanosAndBucketSize_whenShrinkingBucket_clampsCurrentAndUpdatesNanos")
  fun changeNanosAndBucketSize_whenShrinkingBucket_clampsCurrentAndUpdatesNanos() {
    // Arrange (no ticking due to oneDayNanos)
    val throttle = OutputThrottle(maxTokens = 100, nanosPerTick = oneDayNanos, initialTokens = 90)

    // Act
    throttle.changeNanosAndBucketSize(nanosPerTick = 12345L, newMaxTokens = 50)
    val countAfter = throttle.getCount()
    val nanos = throttle.getNanosPerTick()

    // Assert
    assertEquals(50, countAfter, "Current should be clamped to new max")
    assertEquals(12345L, nanos, "nanosPerTick should be updated")
  }

  @Test
  @DisplayName("getNanosPerTick_whenConstructed_returnsInitialValue")
  fun getNanosPerTick_whenConstructed_returnsInitialValue() {
    // Arrange
    val throttle = OutputThrottle(maxTokens = 10, nanosPerTick = 777L, initialTokens = 0)

    // Act
    val nanos = throttle.getNanosPerTick()

    // Assert
    assertEquals(777L, nanos)
  }

  @ParameterizedTest(name = "ctor invalid args: nanosPerTick={0}, maxTokens={1}")
  @CsvSource(
    // nanosPerTick <= 0
    "0, 10",
    "-1, 10",
    // maxTokens <= 0
    "100, 0",
    "100, -5",
    // both invalid
    "0, 0",
    "-10, -10",
  )
  @DisplayName("constructor_whenInvalidArguments_throws")
  fun constructor_whenInvalidArguments_throws(nanosPerTick: Long, maxTokens: Long) {
    // Arrange + Act + Assert
    assertThrows(IllegalArgumentException::class.java) {
      OutputThrottle(maxTokens = maxTokens, nanosPerTick = nanosPerTick, initialTokens = 0)
    }
  }
}

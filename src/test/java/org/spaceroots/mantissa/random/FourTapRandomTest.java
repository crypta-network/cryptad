package org.spaceroots.mantissa.random;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class FourTapRandomTest {

  private static final long FIXED_SEED = 123_456_789L;

  @Test
  void deterministicSequence_whenSeedFixed_expectKnownValues() {
    // Arrange
    FourTapRandom random = new FourTapRandom(FIXED_SEED);

    // Act
    int firstInt = random.nextInt();
    long firstLong = random.nextLong();
    double firstDouble = random.nextDouble();
    random.nextInt();
    random.nextInt();
    long longAfterAdvance = random.nextLong();

    // Assert
    assertEquals(-897_996_993, firstInt);
    assertEquals(2_752_166_806_097_739_985L, firstLong);
    assertEquals(0.6734551010978229d, firstDouble, 0.0d);
    assertEquals(-9_128_342_020_895_779_620L, longAfterAdvance);
  }

  @Test
  void setSeed_whenCalledAfterUsage_resetsSequence() {
    // Arrange
    FourTapRandom random = new FourTapRandom(9_876L);
    int firstValue = random.nextInt();
    random.nextInt();

    // Act
    random.setSeed(9_876L);
    int resetFirstValue = random.nextInt();

    // Assert
    assertEquals(firstValue, resetFirstValue);
  }

  @Test
  void nextInt_whenBufferWraps_returnsConsistentValue() {
    // Arrange
    FourTapRandom random = new FourTapRandom(42L);
    int last = 0;

    // Act
    for (int i = 0; i < 16_383 + 5; i++) {
      last = random.nextInt();
    }

    // Assert
    assertEquals(283_416_378, last);
  }

  @Test
  void next_withVariousBitLengths_returnsUpperBitsOnly() {
    // Arrange
    ExposedFourTapRandom random = new ExposedFourTapRandom(123L);

    // Act
    int singleBit = random.exposedNext(1);
    int fiveBits = random.exposedNext(5);
    int thirtyOneBits = random.exposedNext(31);

    // Assert
    assertEquals(0, singleBit);
    assertEquals(20, fiveBits);
    assertEquals(1_663_352_403, thirtyOneBits);
    assertTrue(thirtyOneBits >= 0); // 31-bit result should be non-negative
  }

  private static final class ExposedFourTapRandom extends FourTapRandom {
    ExposedFourTapRandom(long seed) {
      super(seed);
    }

    int exposedNext(int bits) {
      return super.next(bits);
    }
  }
}

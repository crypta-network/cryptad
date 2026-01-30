package org.spaceroots.mantissa.random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("java:S100")
class MersenneTwisterTest {

  private static final int SEED_5489 = 5489;

  private static final int[] FIRST_TEN_NEXT_INT_FOR_5489 = {
    0xD091BB5C, // 3499211612
    0x22AE9EF6, //  581869302
    0xE7E1FAEE, // 3890346734
    0xD5C31F79, // 3586334585
    0x2082352C, //  545404204
    0xF807B7DF, // 4161255391
    0xE9D30005, // 3922919429
    0x3895AFE1, //  949333985
    0xA1E24BBA, // 2715962298
    0x4EE4092B // 1323567403
  };

  @Test
  void nextInt_whenSeed5489_expectReferenceSequence() {
    // Arrange
    MersenneTwister twister = new MersenneTwister(SEED_5489);

    // Act
    int[] actual = new int[FIRST_TEN_NEXT_INT_FOR_5489.length];
    for (int i = 0; i < actual.length; i++) {
      actual[i] = twister.nextInt();
    }

    // Assert
    assertArrayEquals(FIRST_TEN_NEXT_INT_FOR_5489, actual);
  }

  @Test
  void constructors_whenSameSeed_expectIdenticalSequences() {
    // Arrange
    int seed = 123456789;
    MersenneTwister a = new MersenneTwister(seed);
    MersenneTwister b = new MersenneTwister(seed);

    // Act
    int[] seqA = new int[100];
    int[] seqB = new int[100];
    for (int i = 0; i < seqA.length; i++) {
      seqA[i] = a.nextInt();
      seqB[i] = b.nextInt();
    }

    // Assert
    assertArrayEquals(seqA, seqB);
  }

  @Test
  void setSeed_whenReinitialized_expectSameAsNewInstance() {
    // Arrange
    int seed = 42;
    MersenneTwister twister = new MersenneTwister(1);
    MersenneTwister fresh = new MersenneTwister(seed);

    // Act
    twister.setSeed(seed);
    int[] afterReset = new int[50];
    int[] fromFresh = new int[50];
    for (int i = 0; i < afterReset.length; i++) {
      afterReset[i] = twister.nextInt();
      fromFresh[i] = fresh.nextInt();
    }

    // Assert
    assertArrayEquals(fromFresh, afterReset);
  }

  @Test
  void setSeed_whenIntArray_expectDeterministicSequence() {
    // Arrange
    int[] seed = {1, 2, 3, 4};
    MersenneTwister a = new MersenneTwister(seed);
    MersenneTwister b = new MersenneTwister(seed);

    // Act
    long[] seqA = new long[20];
    long[] seqB = new long[20];
    for (int i = 0; i < seqA.length; i++) {
      seqA[i] = a.nextLong();
      seqB[i] = b.nextLong();
    }

    // Assert
    assertArrayEquals(seqA, seqB);
  }

  @Test
  void setSeed_whenIntArrayNull_expectDelegatesToLongSeed() {
    // Arrange
    CapturingTwister twister = new CapturingTwister();

    // Act
    assertDoesNotThrow(() -> twister.setSeed(null));

    // Assert
    assertNotNull(twister.capturedLongSeed);
  }

  @ParameterizedTest
  @MethodSource("longSeeds")
  void constructor_whenLongSeed_expectSameAsIntArrayHighLow(long seed) {
    // Arrange
    int high = (int) (seed >>> 32);
    int low = (int) (seed & 0xffffffffL);
    MersenneTwister fromLong = new MersenneTwister(seed);
    MersenneTwister fromInts = new MersenneTwister(new int[] {high, low});

    // Act
    int[] seqLong = new int[64];
    int[] seqInts = new int[64];
    for (int i = 0; i < seqLong.length; i++) {
      seqLong[i] = fromLong.nextInt();
      seqInts[i] = fromInts.nextInt();
    }

    // Assert
    assertArrayEquals(seqInts, seqLong);
  }

  @Test
  void next_whenBits32_expectMatchesNextInt() {
    // Arrange
    ExposedTwister twister = new ExposedTwister(SEED_5489);
    MersenneTwister base = new MersenneTwister(SEED_5489);

    // Act
    int viaNext = twister.nextBits(32);
    int viaNextInt = base.nextInt();

    // Assert
    assertEquals(viaNextInt, viaNext);
  }

  @Test
  void next_whenBitsZero_expectSameAsBits32DueToShiftMasking() {
    // Arrange
    ExposedTwister zeroBits = new ExposedTwister(123);
    ExposedTwister fullBits = new ExposedTwister(123);

    // Act
    int viaZero = zeroBits.nextBits(0);
    int viaFull = fullBits.nextBits(32);

    // Assert
    assertEquals(viaFull, viaZero);
  }

  @ParameterizedTest
  @MethodSource("bitSizes")
  void next_whenVariousBits_expectWithinRange(int bits) {
    // Arrange
    ExposedTwister twister = new ExposedTwister(987654321);

    // Act
    int value = twister.nextBits(bits);

    // Assert
    long unsignedValue = value & 0xffffffffL;
    long maxExclusive = bits == 32 ? 0x1_0000_0000L : (1L << bits);
    assertTrue(unsignedValue < maxExclusive);
  }

  @Test
  void sequences_whenDifferentSeeds_expectDifferentEarlyValues() {
    // Arrange
    MersenneTwister a = new MersenneTwister(1);
    MersenneTwister b = new MersenneTwister(2);

    // Act
    int firstA = a.nextInt();
    int firstB = b.nextInt();

    // Assert
    assertNotEquals(firstA, firstB);
  }

  private static Stream<Long> longSeeds() {
    return Stream.of(0L, 1L, -1L, Long.MIN_VALUE, Long.MAX_VALUE, 0x0123456789ABCDEFL);
  }

  private static Stream<Integer> bitSizes() {
    return Stream.of(1, 7, 16, 31, 32);
  }

  private static final class ExposedTwister extends MersenneTwister {
    ExposedTwister(int seed) {
      super(seed);
    }

    int nextBits(int bits) {
      return super.next(bits);
    }
  }

  private static final class CapturingTwister extends MersenneTwister {
    private Long capturedLongSeed;

    CapturingTwister() {
      super(0);
    }

    @Override
    public synchronized void setSeed(long seed) {
      this.capturedLongSeed = seed;
    }
  }
}

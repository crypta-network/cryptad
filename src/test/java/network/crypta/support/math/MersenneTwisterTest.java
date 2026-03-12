package network.crypta.support.math;

import java.lang.reflect.Modifier;
import java.util.stream.Stream;
import network.crypta.support.Fields;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.ThrowingSupplier;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit tests for {@link MersenneTwister} wrapper.
 *
 * <p>Tests compare sequences against the upstream implementation {@link
 * org.spaceroots.mantissa.random.MersenneTwister} to ensure behavioral compatibility. All seeds are
 * deterministic; tests avoid the time-based constructors to prevent flakiness.
 */
class MersenneTwisterTest {

  // Generate a moderate number of values to validate sequence equality while keeping tests fast.
  private static final int SEQ_LEN = 128;

  // ----- Parameter sources -----

  private static Stream<Integer> intSeeds() {
    return Stream.of(0, 1, -1, 123456789, Integer.MIN_VALUE, Integer.MAX_VALUE);
  }

  private static Stream<Long> longSeeds() {
    return Stream.of(0L, 1L, -1L, 0x0123456789ABCDEFL, Long.MIN_VALUE, Long.MAX_VALUE);
  }

  private static Stream<Arguments> intArraySeeds() {
    return Stream.of(
        Arguments.of((Object) new int[] {42}),
        Arguments.of((Object) new int[] {0xCAFEBABE}),
        Arguments.of((Object) new int[] {1, 2}),
        Arguments.of((Object) new int[] {0, -1, Integer.MIN_VALUE, Integer.MAX_VALUE}));
  }

  private static Stream<Arguments> validByteArraySeeds() {
    // Use Fields.intsToBytes() to create byte[] that reversibly maps to int[] via bytesToInts().
    return Stream.of(
        Arguments.of((Object) Fields.intsToBytes(new int[] {42})),
        Arguments.of((Object) Fields.intsToBytes(new int[] {0xCAFEBABE})),
        Arguments.of((Object) Fields.intsToBytes(new int[] {1, 2})),
        Arguments.of(
            (Object) Fields.intsToBytes(new int[] {0, -1, Integer.MIN_VALUE, Integer.MAX_VALUE})));
  }

  private static Stream<byte[]> invalidLengthByteArraySeeds() {
    return Stream.of(
        new byte[] {1}, new byte[] {1, 2}, new byte[] {1, 2, 3}, new byte[] {1, 2, 3, 4, 5});
  }

  // ----- Tests comparing against upstream implementation -----

  @ParameterizedTest
  @MethodSource("intSeeds")
  @DisplayName("nextInt_whenSeededWithInt_sameSequenceAsUpstream")
  void nextInt_whenSeededWithInt_sameSequenceAsUpstream(int seed) {
    // Arrange
    MersenneTwister ours = new MersenneTwister(seed);
    org.spaceroots.mantissa.random.MersenneTwister upstream =
        new org.spaceroots.mantissa.random.MersenneTwister(seed);

    // Act & Assert
    for (int i = 0; i < SEQ_LEN; i++) {
      assertEquals(upstream.nextInt(), ours.nextInt(), "Mismatch at index " + i);
    }
  }

  @ParameterizedTest
  @MethodSource("longSeeds")
  @DisplayName("nextInt_whenSeededWithLong_sameSequenceAsUpstream")
  void nextInt_whenSeededWithLong_sameSequenceAsUpstream(long seed) {
    // Arrange
    MersenneTwister ours = new MersenneTwister(seed);
    org.spaceroots.mantissa.random.MersenneTwister upstream =
        new org.spaceroots.mantissa.random.MersenneTwister(seed);

    // Act & Assert
    for (int i = 0; i < SEQ_LEN; i++) {
      assertEquals(upstream.nextInt(), ours.nextInt(), "Mismatch at index " + i);
    }
  }

  @ParameterizedTest
  @MethodSource("intArraySeeds")
  @DisplayName("nextInt_whenSeededWithIntArray_sameSequenceAsUpstream")
  void nextInt_whenSeededWithIntArray_sameSequenceAsUpstream(int[] seed) {
    // Arrange
    MersenneTwister ours = new MersenneTwister(seed);
    org.spaceroots.mantissa.random.MersenneTwister upstream =
        new org.spaceroots.mantissa.random.MersenneTwister(seed);

    // Act & Assert
    for (int i = 0; i < SEQ_LEN; i++) {
      assertEquals(upstream.nextInt(), ours.nextInt(), "Mismatch at index " + i);
    }
  }

  @ParameterizedTest
  @MethodSource("validByteArraySeeds")
  @DisplayName("nextInt_whenSeededWithByteArray_sameSequenceAsUpstreamConvertedInts")
  void nextInt_whenSeededWithByteArray_sameSequenceAsUpstreamConvertedInts(byte[] seed) {
    // Arrange
    MersenneTwister ours = new MersenneTwister(123); // placeholder seed, will be replaced
    ours.setSeed(seed);

    int[] ints = Fields.bytesToInts(seed);
    org.spaceroots.mantissa.random.MersenneTwister upstream =
        new org.spaceroots.mantissa.random.MersenneTwister(ints);

    // Act & Assert
    for (int i = 0; i < SEQ_LEN; i++) {
      assertEquals(upstream.nextInt(), ours.nextInt(), "Mismatch at index " + i);
    }
  }

  @ParameterizedTest
  @MethodSource("validByteArraySeeds")
  @DisplayName("nextInt_whenCreatedUnsynchronizedByteSeed_matchesSynchronized")
  void nextInt_whenCreatedUnsynchronizedByteSeed_matchesSynchronized(byte[] seed) {
    // Arrange
    MersenneTwister sync = MersenneTwister.createSynchronized(seed);
    MersenneTwister unsync = MersenneTwister.createUnsynchronized(seed);

    // Act & Assert
    for (int i = 0; i < SEQ_LEN; i++) {
      assertEquals(sync.nextInt(), unsync.nextInt(), "Mismatch at index " + i);
    }
  }

  @ParameterizedTest
  @MethodSource("intSeeds")
  @DisplayName("nextGaussian_whenSameIntSeed_matchesUpstream")
  void nextGaussian_whenSameIntSeed_matchesUpstream(int seed) {
    // Arrange
    MersenneTwister ours = new MersenneTwister(seed);
    org.spaceroots.mantissa.random.MersenneTwister upstream =
        new org.spaceroots.mantissa.random.MersenneTwister(seed);

    // Act & Assert
    for (int i = 0; i < SEQ_LEN; i++) {
      assertEquals(upstream.nextGaussian(), ours.nextGaussian(), 0.0, "Mismatch at index " + i);
    }
  }

  @Test
  @DisplayName("nextBytes_whenSameSeed_equalOutput")
  void nextBytes_whenSameSeed_equalOutput() {
    // Arrange
    int seed = 987654321;
    MersenneTwister ours = new MersenneTwister(seed);
    org.spaceroots.mantissa.random.MersenneTwister upstream =
        new org.spaceroots.mantissa.random.MersenneTwister(seed);
    byte[] b1 = new byte[64];
    byte[] b2 = new byte[64];

    // Act
    ours.nextBytes(b1);
    upstream.nextBytes(b2);

    // Assert
    assertArrayEquals(b2, b1);
  }

  @Test
  @DisplayName("nextBytes_whenZeroLength_noChangeAndNoException")
  void nextBytes_whenZeroLength_noChangeAndNoException() {
    // Arrange
    int seed = 13579;
    MersenneTwister ours = new MersenneTwister(seed);
    byte[] empty = new byte[0];

    // Act & Assert
    assertDoesNotThrow(() -> ours.nextBytes(empty));
    assertEquals(0, empty.length);
  }

  @Test
  @DisplayName("setSeed_whenCalledTwiceWithSameIntSeed_resetsSequence")
  void setSeed_whenCalledTwiceWithSameIntSeed_resetsSequence() {
    // Arrange
    int seed = 424242;
    MersenneTwister ours = new MersenneTwister(seed);

    int firstA = ours.nextInt();
    int secondA = ours.nextInt();

    // Act
    ours.setSeed(seed);

    int firstB = ours.nextInt();
    int secondB = ours.nextInt();

    // Assert
    assertEquals(firstA, firstB);
    assertEquals(secondA, secondB);
  }

  // ----- Null and invalid input paths -----

  @Test
  @DisplayName("setSeed_whenIntArrayNull_doesNotThrow")
  void setSeed_whenIntArrayNull_doesNotThrow() {
    // Arrange
    MersenneTwister ours = new MersenneTwister(123);

    // Act & Assert: Upstream supports null -> time-based seed; wrapper forwards to super.
    assertDoesNotThrow(() -> ours.setSeed((int[]) null));
    // Also exercise that generator remains usable.
    assertDoesNotThrow((ThrowingSupplier<Integer>) ours::nextInt);
  }

  @Test
  @DisplayName("setSeed_whenByteArrayNull_throwsNullPointerException")
  void setSeed_whenByteArrayNull_throwsNullPointerException() {
    // Arrange
    MersenneTwister ours = new MersenneTwister(123);

    // Act + Assert
    assertThrows(NullPointerException.class, () -> ours.setSeed((byte[]) null));
  }

  @ParameterizedTest
  @MethodSource("invalidLengthByteArraySeeds")
  @DisplayName("setSeed_whenByteArrayNotMultipleOf4_throwsIllegalArgumentException")
  void setSeed_whenByteArrayNotMultipleOf4_throwsIllegalArgumentException(byte[] badSeed) {
    // Arrange
    MersenneTwister ours = new MersenneTwister(123);

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> ours.setSeed(badSeed));
  }

  @Test
  @DisplayName("setSeed_whenEmptyByteArray_throwsArrayIndexOutOfBoundsException")
  void setSeed_whenEmptyByteArray_throwsArrayIndexOutOfBoundsException() {
    // Arrange
    MersenneTwister ours = new MersenneTwister(123);
    byte[] empty = new byte[0];

    // Act + Assert: bytesToInts(empty) -> empty int[], upstream setSeed(int[]) will access seed[0]
    assertThrows(ArrayIndexOutOfBoundsException.class, () -> ours.setSeed(empty));
  }

  @ParameterizedTest
  @MethodSource("invalidLengthByteArraySeeds")
  @DisplayName("createSynchronized_whenByteArrayNotMultipleOf4_throwsIllegalArgumentException")
  void createSynchronized_whenByteArrayNotMultipleOf4_throwsIllegalArgumentException(
      byte[] badSeed) {
    assertThrows(IllegalArgumentException.class, () -> MersenneTwister.createSynchronized(badSeed));
  }

  @ParameterizedTest
  @MethodSource("invalidLengthByteArraySeeds")
  @DisplayName("createUnsynchronized_whenByteArrayNotMultipleOf4_throwsIllegalArgumentException")
  void createUnsynchronized_whenByteArrayNotMultipleOf4_throwsIllegalArgumentException(
      byte[] badSeed) {
    assertThrows(
        IllegalArgumentException.class, () -> MersenneTwister.createUnsynchronized(badSeed));
  }

  @Test
  @DisplayName("createSynchronized_whenEmptyByteArray_throwsArrayIndexOutOfBoundsException")
  void createSynchronized_whenEmptyByteArray_throwsArrayIndexOutOfBoundsException() {
    assertThrows(
        ArrayIndexOutOfBoundsException.class,
        () -> MersenneTwister.createSynchronized(new byte[0]));
  }

  @Test
  @DisplayName("createUnsynchronized_whenEmptyByteArray_throwsArrayIndexOutOfBoundsException")
  void createUnsynchronized_whenEmptyByteArray_throwsArrayIndexOutOfBoundsException() {
    assertThrows(
        ArrayIndexOutOfBoundsException.class,
        () -> MersenneTwister.createUnsynchronized(new byte[0]));
  }

  @Test
  @DisplayName("createMethods_whenByteArrayNull_throwsNullPointerException")
  void createMethods_whenByteArrayNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> MersenneTwister.createSynchronized(null));
    assertThrows(NullPointerException.class, () -> MersenneTwister.createUnsynchronized(null));
  }

  // ----- Byte/int conversions and cross-API consistency -----

  @Test
  @DisplayName("setSeed_whenByteArrayEqualsIntsConversion_sameSequence")
  void setSeed_whenByteArrayEqualsIntsConversion_sameSequence() {
    // Arrange
    int[] ints = new int[] {0x01234567, 0x89ABCDEF};
    byte[] bytes = Fields.intsToBytes(ints);
    MersenneTwister viaBytes = new MersenneTwister(0);
    viaBytes.setSeed(bytes);

    MersenneTwister viaInts = new MersenneTwister(0);
    viaInts.setSeed(ints);

    // Act & Assert
    for (int i = 0; i < SEQ_LEN; i++) {
      assertEquals(viaInts.nextLong(), viaBytes.nextLong(), "Mismatch at index " + i);
    }
  }

  @Test
  @DisplayName("unsynchronizedAndSynchronized_whenSameSeed_produceIdenticalSequence")
  void unsynchronizedAndSynchronized_whenSameSeed_produceIdenticalSequence() {
    // Arrange
    byte[] seed = Fields.intsToBytes(new int[] {123456789});
    MersenneTwister sync = MersenneTwister.createSynchronized(seed);
    MersenneTwister unsync = MersenneTwister.createUnsynchronized(seed);

    // Act & Assert
    for (int i = 0; i < SEQ_LEN; i++) {
      assertEquals(sync.nextLong(), unsync.nextLong(), "Mismatch at index " + i);
    }
  }

  @Test
  @DisplayName("createUnsynchronized_whenInspectOverrides_expectNonSynchronizedMethods")
  void createUnsynchronized_whenInspectOverrides_expectNonSynchronizedMethods()
      throws NoSuchMethodException {
    // Arrange
    byte[] seed = Fields.intsToBytes(new int[] {123456789});
    MersenneTwister unsync = MersenneTwister.createUnsynchronized(seed);
    Class<?> implementationClass = unsync.getClass();

    // Assert
    assertFalse(
        Modifier.isSynchronized(
            implementationClass.getDeclaredMethod("next", int.class).getModifiers()));
    assertFalse(
        Modifier.isSynchronized(
            implementationClass.getDeclaredMethod("setSeed", int.class).getModifiers()));
    assertFalse(
        Modifier.isSynchronized(
            implementationClass.getDeclaredMethod("setSeed", int[].class).getModifiers()));
    assertFalse(
        Modifier.isSynchronized(
            implementationClass.getDeclaredMethod("setSeed", long.class).getModifiers()));
  }

  @Test
  @DisplayName("randomApiParity_whenSameSeed_matchesForAllPrimitives")
  void randomApiParity_whenSameSeed_matchesForAllPrimitives() {
    // Arrange
    int seed = 2468;
    MersenneTwister ours = new MersenneTwister(seed);
    org.spaceroots.mantissa.random.MersenneTwister upstream =
        new org.spaceroots.mantissa.random.MersenneTwister(seed);

    // Act & Assert across various Random methods
    for (int i = 0; i < SEQ_LEN; i++) {
      assertEquals(upstream.nextBoolean(), ours.nextBoolean(), "boolean @" + i);
      assertEquals(upstream.nextFloat(), ours.nextFloat(), 0.0f, "float @" + i);
      assertEquals(upstream.nextDouble(), ours.nextDouble(), 0.0, "double @" + i);
      assertEquals(upstream.nextLong(), ours.nextLong(), "long @" + i);
    }
  }
}

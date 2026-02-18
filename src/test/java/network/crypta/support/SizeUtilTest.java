package network.crypta.support;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests for {@link SizeUtil}. IEC units, spacing variants, negatives, and boundaries are covered.
 */
@SuppressWarnings("java:S100") // test naming style: method_whenCondition_expectOutcome
class SizeUtilTest {

  private static void assertFormattedEquals(long bytes, String expected) {
    String actual = SizeUtil.formatSize(bytes);
    assertEquals(expected, actual);
  }

  // region: exact powers of 1024

  @ParameterizedTest(name = "{0} bytes -> {1}")
  @CsvSource({
    // e=0..6 (B..EiB)
    "1,1 B",
    "1024,1.0 KiB",
    "1048576,1.0 MiB",
    "1073741824,1.0 GiB",
    "1099511627776,1.0 TiB",
    "1125899906842624,1.0 PiB",
    "1152921504606846976,1.0 EiB"
  })
  void formatSize_whenExactPowerOf1024_expectExpectedUnitAndMantissa(long bytes, String expected) {
    // Act + Assert
    assertFormattedEquals(bytes, expected);
  }

  // endregion

  // region: quarters within a unit (KiB..EiB)

  static long[] unitBases() {
    return new long[] {
      1024L,
      1024L * 1024,
      1024L * 1024 * 1024,
      1099511627776L, // TiB
      1125899906842624L, // PiB
      1152921504606846976L // EiB
    };
  }

  @ParameterizedTest
  @MethodSource("unitBases")
  void formatSize_whenIntermediateQuarters_expectCorrectMantissa(long base) {
    // Arrange
    String unit = unitNameForBase(base);
    String[] expectedMantissas = {"1.0", "1.25", "1.5", "1.75"};

    // Act + Assert
    for (int q = 0; q < 4; q++) {
      long bytes = base + (base * q) / 4; // exact integer arithmetic
      String actual = SizeUtil.formatSize(bytes);
      assertEquals(expectedMantissas[q] + " " + unit, actual);
    }
  }

  private static String unitNameForBase(long base) {
    if (base == 1024L) return "KiB";
    if (base == 1024L * 1024) return "MiB";
    if (base == 1024L * 1024 * 1024) return "GiB";
    if (base == 1099511627776L) return "TiB";
    if (base == 1125899906842624L) return "PiB";
    if (base == 1152921504606846976L) return "EiB";
    throw new IllegalArgumentException("Unexpected base: " + base);
  }

  // endregion

  // region: spacing variants

  @Test
  void formatSize_whenNonBreakingSpaceRequested_expectNBSPBetweenNumberAndUnit() {
    // Arrange
    long bytes = 1024L;
    // Act
    String actual = SizeUtil.formatSize(bytes, true);
    // Assert
    assertEquals("1.0\u00A0KiB", actual);
  }

  @Test
  void formatSizeWithoutSpace_whenExactKiB_expectNoSeparator() {
    // Arrange
    long bytes = 1024L;
    // Act
    String actual = SizeUtil.formatSizeWithoutSpace(bytes);
    // Assert
    assertEquals("1.0KiB", actual);
  }

  // endregion

  // region: negatives and boundaries

  @ParameterizedTest
  @CsvSource({"0,0 B", "1023,1023 B", "-1,-1 B", "-1024,-1.0 KiB", "-1536,-1.5 KiB"})
  void formatSize_whenEdgeValues_expectExpectedStrings(long bytes, String expected) {
    // Act + Assert
    assertFormattedEquals(bytes, expected);
  }

  @Test
  @DisplayName("Mantissa with three digits before dot is trimmed: 100 KiB")
  void formatSize_whenHundredKiB_expectNoDecimalPart() {
    // Arrange
    long bytes = 100L * 1024;
    // Act + Assert
    assertFormattedEquals(bytes, "100 KiB");
  }

  @Test
  void formatSize_whenJustBelowNextUnit_expectStaysInLowerUnit() {
    // Arrange
    long bytes = (1024L * 1024) - 1; // 1 MiB - 1 byte
    // Act + Assert (truncation to 4 chars yields "1023 KiB")
    assertFormattedEquals(bytes, "1023 KiB");
  }

  @Test
  void formatSize_whenLargeExactEiBMultiple_expectStableMantissa() {
    // Arrange
    long bytes = 4L << 60; // 4 EiB
    // Act + Assert
    assertFormattedEquals(bytes, "4.0 EiB");
  }

  // endregion
}

package network.crypta.support;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Locale;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test case for {@link Fields} class.
 *
 * @author stuart martin &lt;wavey@freenetproject.org&gt;
 */
@SuppressWarnings("java:S100")
class FieldsTest {

  @ParameterizedTest
  @CsvSource({
    "0,0",
    "000000,0",
    "1,1",
    "a,10",
    "ff,255",
    "ffffffff,4294967295",
    "7fffffffffffffff,9223372036854775807",
    "8000000000000000,-9223372036854775808",
    "FFfffFfF,4294967295"
  })
  void hexToLong_whenValidHex_expectCorrectValue(String hex, long expected) {
    // Arrange
    // Act
    long actual = Fields.hexToLong(hex);
    // Assert
    assertEquals(expected, actual);
  }

  @Test
  void hexToLong_whenJavadocExamples_expectCorrect() {
    // Arrange
    String pos = Long.toHexString(20);
    String min = Long.toHexString(Long.MIN_VALUE);
    // Act & Assert
    assertEquals(20L, Fields.hexToLong(pos));
    assertEquals(Long.MIN_VALUE, Fields.hexToLong(min));
  }

  @ParameterizedTest
  @ValueSource(strings = {"abcdef123456789aa", "DeADC0dER", "-1"})
  void hexToLong_whenInvalid_expectNumberFormatException(String input) {
    // Arrange / Act / Assert
    assertThrows(NumberFormatException.class, () -> Fields.hexToLong(input));
  }

  @ParameterizedTest
  @CsvSource({
    "0,0",
    "000000,0",
    "1,1",
    "a,10",
    "ff,255",
    "80000000,-2147483648",
    "0000000080000000,-2147483648",
    "7fffffff,2147483647"
  })
  void hexToInt_whenValidHex_expectCorrectValue(String hex, int expected) {
    // Act
    int actual = Fields.hexToInt(hex);
    // Assert
    assertEquals(expected, actual);
  }

  @Test
  void hexToInt_whenJavadocExamples_expectCorrect() {
    assertEquals(20, Fields.hexToInt(Integer.toHexString(20)));
    assertEquals(Integer.MIN_VALUE, Fields.hexToInt(Long.toHexString(Integer.MIN_VALUE)));
  }

  @ParameterizedTest
  @ValueSource(strings = {"0123456789abcdef0", "C0dER", "-1"})
  void hexToInt_whenInvalid_expectNumberFormatException(String input) {
    assertThrows(NumberFormatException.class, () -> Fields.hexToInt(input));
  }

  @ParameterizedTest
  @CsvSource({"true,true", "TRUE,true", "false,false", "FALSE,false", "yes,true", "no,false"})
  void stringToBool_whenValid_expectParsed(String input, boolean expected) {
    boolean actual = Fields.stringToBool(input);
    assertEquals(expected, actual);
  }

  @ParameterizedTest
  @ValueSource(strings = {"Free Tibet", "maybe"})
  void stringToBool_whenInvalid_expectNumberFormatException(String input) {
    assertThrows(NumberFormatException.class, () -> Fields.stringToBool(input));
  }

  @Test
  void stringToBool_whenNull_expectNumberFormatException() {
    assertThrows(NumberFormatException.class, () -> Fields.stringToBool(null));
  }

  @ParameterizedTest
  @CsvSource({
    "true,false,true",
    "false,true,false",
    "TruE,false,true",
    "faLSE,true,false",
    "trueXXX,true,true",
    "XXXFalse,false,false"
  })
  void stringToBool_withDefault_expectFallbackOrParse(String input, boolean def, boolean expected) {
    boolean actual = Fields.stringToBool(input, def);
    assertEquals(expected, actual);
  }

  @Test
  void stringToBool_withDefault_whenNull_expectDefault() {
    assertTrue(Fields.stringToBool(null, true));
  }

  @Test
  void boolToString_whenGivenBooleans_expectCorrectStrings() {
    assertEquals("true", Fields.boolToString(true));
    assertEquals("false", Fields.boolToString(false));
  }

  @Test
  void commaList_whenParsingString_expectTrimmedTokens() {
    // Arrange
    String input = "one,two,     three    ,  four";
    String[] expected = {"one", "two", "three", "four"};
    // Act
    String[] actual = Fields.commaList(input);
    // Assert
    assertArrayEquals(expected, actual);
  }

  @Test
  void commaList_whenNullString_expectEmptyArray() {
    assertNotNull(Fields.commaList((String) null));
    assertEquals(0, Fields.commaList((String) null).length);
  }

  @Test
  void commaList_whenEmptyString_expectEmptyArray() {
    assertEquals(0, Fields.commaList("").length);
  }

  @Test
  void commaList_whenArray_expectJoinedWithCommas() {
    assertEquals(
        "one,two,three,four", Fields.commaList(new String[] {"one", "two", "three", "four"}));
  }

  @Test
  void commaList_whenArrayEmpty_expectEmptyString() {
    assertEquals("", Fields.commaList(new String[] {}));
  }

  @Test
  void hashCode_whenNonEmptyAndEmpty_expectExpectedValues() {
    byte[] input = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};

    assertEquals(67372036, Fields.hashCode(input));

    // empty
    input = new byte[] {};

    assertEquals(0, Fields.hashCode(input));
  }

  @Test
  void longHashCode_whenDifferentAndEqualArrays_expectExpectedRelations() {

    byte[] b1 = new byte[] {1, 1, 2, 2, 3, 3};
    byte[] b2 = new byte[] {2, 2, 3, 3, 4, 4};
    byte[] b3 = new byte[] {1, 1, 2, 2, 3, 3};

    Long l1 = Fields.longHashCode(b1);
    Long l2 = Fields.longHashCode(b2);
    Long l3 = Fields.longHashCode(b3);

    assertNotEquals(l1, l2);
    assertNotEquals(l2, l3);
    assertEquals(l3, l1); // should be same due to Fields.longHashcode
  }

  @Test
  void intsToBytes_whenRoundTripVariousInputs_expectEquality() {
    int[] longs = new int[] {};
    doRoundTripIntsArrayToBytesArray(longs);

    longs = new int[] {Integer.MIN_VALUE};
    doRoundTripIntsArrayToBytesArray(longs);

    longs = new int[] {0, Integer.MAX_VALUE, Integer.MIN_VALUE};
    doRoundTripIntsArrayToBytesArray(longs);

    longs = new int[] {33685760, 51511577};
    doRoundTripIntsArrayToBytesArray(longs);
  }

  private void doRoundTripIntsArrayToBytesArray(int[] ints) {
    // Arrange
    // Act
    byte[] bytes = Fields.intsToBytes(ints);
    int[] out = Fields.bytesToInts(bytes);
    // Assert
    assertEquals(ints.length * 4, bytes.length);
    assertArrayEquals(ints, out);
  }

  @Test
  void bytesToLongs_whenLengthNotMultipleOfEight_expectException() {
    byte[] bytes = new byte[3];
    assertThrows(IllegalArgumentException.class, () -> Fields.bytesToLongs(bytes, 0, bytes.length));
  }

  @Test
  void bytesToInt_whenValid_expectCorrect() {
    byte[] bytes = new byte[] {0, 1, 2, 2};
    int value = Fields.bytesToInt(bytes, 0);
    assertEquals(33685760, value);
  }

  @Test
  void bytesToInt_whenRoundTrip_expectEqual() {
    byte[] bytes = new byte[] {1, 1, 1, 1};
    doTestRoundTripBytesArrayToInt(bytes);
  }

  @Test
  void bytesToInt_whenTooShort_expectException() {
    assertThrows(
        IllegalArgumentException.class, () -> doTestRoundTripBytesArrayToInt(new byte[] {}));
  }

  private void doTestRoundTripBytesArrayToInt(byte[] inBytes) {
    // Arrange / Act
    int value = Fields.bytesToInt(inBytes, 0);
    byte[] outBytes = Fields.intToBytes(value);
    // Assert
    assertArrayEquals(inBytes, outBytes);
  }

  @Test
  void longsToBytes_whenRoundTripVariousInputs_expectEquality() {
    long[] longs = new long[] {};
    doRoundTripLongsArrayToBytesArray(longs);

    longs = new long[] {Long.MIN_VALUE};
    doRoundTripLongsArrayToBytesArray(longs);

    longs = new long[] {0L, Long.MAX_VALUE, Long.MIN_VALUE};
    doRoundTripLongsArrayToBytesArray(longs);

    longs = new long[] {3733393793879837L};
    doRoundTripLongsArrayToBytesArray(longs);
  }

  private void doRoundTripLongsArrayToBytesArray(long[] longs) {
    // Arrange / Act
    byte[] bytes = Fields.longsToBytes(longs);
    long[] out = Fields.bytesToLongs(bytes);
    // Assert
    assertEquals(longs.length * 8, bytes.length);
    assertArrayEquals(longs, out);
  }

  @Test
  void bytesToLongException_whenLengthNotMultipleOfEight_expectException() {
    // Use the single-long conversion path to cover a different API surface than the previous test
    byte[] tooShort = new byte[7];
    assertThrows(IllegalArgumentException.class, () -> Fields.bytesToLong(tooShort));
    // Also validate the offset variant fails when remaining bytes < 8
    byte[] nineBytes = new byte[9];
    assertThrows(IllegalArgumentException.class, () -> Fields.bytesToLong(nineBytes, 2));
  }

  @Test
  void bytesToLong_whenValid_expectCorrectAndRoundTrip() {
    byte[] bytes = new byte[] {0, 1, 2, 2, 1, 3, 6, 7};
    long value = Fields.bytesToLong(bytes);
    assertEquals(506095310989295872L, value);
    doTestRoundTripBytesArrayToLong(bytes);
  }

  @Test
  void bytesToLong_whenTooShort_expectException() {
    assertThrows(
        IllegalArgumentException.class, () -> doTestRoundTripBytesArrayToLong(new byte[] {}));
  }

  @Test
  void bytesToLong_whenAllOnes_expectRoundTrip() {
    doTestRoundTripBytesArrayToLong(new byte[] {1, 1, 1, 1, 1, 1, 1, 1});
  }

  private void doTestRoundTripBytesArrayToLong(byte[] inBytes) {
    long value = Fields.bytesToLong(inBytes);
    byte[] outBytes = Fields.longToBytes(value);
    assertArrayEquals(inBytes, outBytes);
  }

  @ParameterizedTest
  @CsvSource({
    "'', ''",
    "'\n',''",
    "'a','a\n'",
    "'a\n','a\n'",
    "' a\n','a\n'",
    "' a \n','a\n'",
    "'\na','a\n'",
    "'\na\n','a\n'",
    "'a\nb','a\nb\n'"
  })
  void trimLines_whenInput_expectNormalized(String input, String expected) {
    assertEquals(expected, Fields.trimLines(input));
  }

  @Test
  void getDigits_whenAlternatingDigitsAndNonDigits_expectCorrectCounts() {
    assertEquals(1, Fields.getDigits("1.0", 0, true));
    assertEquals(0, Fields.getDigits("1.0", 0, false));
    assertEquals(1, Fields.getDigits("1.0", 1, false));
    assertEquals(0, Fields.getDigits("1.0", 1, true));
    assertEquals(1, Fields.getDigits("1.0", 2, true));
    assertEquals(0, Fields.getDigits("1.0", 2, false));
    Random r = new Random(88888);
    for (int i = 0; i < 1024; i++) {
      int digits = r.nextInt(20) + 1;
      int nonDigits = r.nextInt(20) + 1;
      int digits2 = r.nextInt(20) + 1;
      String s =
          generateDigits(r, digits) + generateNonDigits(r, nonDigits) + generateDigits(r, digits2);
      assertEquals(0, Fields.getDigits(s, 0, false));
      assertEquals(digits, Fields.getDigits(s, 0, true));
      assertEquals(nonDigits, Fields.getDigits(s, digits, false));
      assertEquals(0, Fields.getDigits(s, digits, true));
      assertEquals(digits2, Fields.getDigits(s, digits + nonDigits, true));
      assertEquals(0, Fields.getDigits(s, digits + nonDigits, false));
    }
  }

  private String generateDigits(Random r, int count) {
    StringBuilder sb = new StringBuilder(count);
    for (int i = 0; i < count; i++) {
      char c = (char) ('0' + r.nextInt(10));
      sb.append(c);
    }
    return sb.toString();
  }

  private String generateNonDigits(Random r, int count) {
    final String ALPHABET = "abcdefghijklmnopqrstuvwxyz";
    final String NONDIGITS = "./\\_=+:" + ALPHABET + ALPHABET.toUpperCase(Locale.ROOT);
    StringBuilder sb = new StringBuilder(count);
    for (int i = 0; i < count; i++) sb.append(NONDIGITS.charAt(r.nextInt(NONDIGITS.length())));
    return sb.toString();
  }

  @ParameterizedTest
  @CsvSource({
    "1.0,1.1",
    "1.0,1.01",
    "1.0,2.0",
    "1.0,11.0",
    "1.0,1.0.1",
    "1,1.1",
    "1,2",
    "test 1.0,test 1.1",
    "best 1.0,test 1.0",
    "test 1.0,testing 1.0",
    "1.0,test 1.0"
  })
  void compareVersion_whenLessThan_expectOrdering(String a, String b) {
    // Arrange / Act
    int ab = Fields.compareVersion(a, b);
    int ba = Fields.compareVersion(b, a);
    // Assert
    assertTrue(ab < 0);
    assertTrue(ba > 0);
    assertEquals(0, Fields.compareVersion(a, a));
    assertEquals(0, Fields.compareVersion(b, b));
  }

  @Test
  void parseLong_whenOverflow_expectNumberFormatException() {
    NumberFormatException ex =
        assertThrows(NumberFormatException.class, () -> Fields.parseLong("9999999999GiB"));
    assertEquals("Long overflow", ex.getMessage());
  }

  // New tests below aim to improve coverage of Fields.java public API.

  @Test
  void numberList_whenRoundTrip_expectEqual() {
    long[] input = new long[] {0, 1, 0xA, 0xFF, 0x7FFFFFFF, 0x80000000L};
    String hexList = Fields.numberList(input);
    long[] parsed = Fields.numberList(hexList);
    assertArrayEquals(input, parsed);
  }

  @Test
  void dateTime_whenValidDateOnly_expectMidnightMillis() {
    String date = "20240102"; // 2024-01-02 00:00:00 local time
    long actual = Fields.dateTime(date);
    long expected =
        LocalDateTime.of(2024, 1, 2, 0, 0, 0)
            .atZone(ZoneId.systemDefault())
            .toInstant()
            .toEpochMilli();
    assertEquals(expected, actual);
  }

  @Test
  void dateTime_whenValidDateAndTime_expectExactMillis() {
    String date = "20240102-03:04:05"; // 2024-01-02 03:04:05 local time
    long actual = Fields.dateTime(date);
    long expected =
        LocalDateTime.of(2024, 1, 2, 3, 4, 5)
            .atZone(ZoneId.systemDefault())
            .toInstant()
            .toEpochMilli();
    assertEquals(expected, actual);
  }

  @Test
  void dateTime_whenEmpty_expectNumberFormatException() {
    NumberFormatException ex = assertThrows(NumberFormatException.class, () -> Fields.dateTime(""));
    assertEquals("Date time empty", ex.getMessage());
  }

  @Test
  void dateTime_whenInvalidFormat_expectNumberFormatException() {
    assertThrows(NumberFormatException.class, () -> Fields.dateTime("2024-0102"));
    assertThrows(NumberFormatException.class, () -> Fields.dateTime("20240102-000000"));
  }

  @Test
  void secToDateTime_whenMidnight_expectDateOnly() {
    // 1970-01-01 00:00:00 UTC
    assertEquals("19700101", Fields.secToDateTime(0));
  }

  @Test
  void secToDateTime_whenHasTime_expectFullTimestamp() {
    assertEquals("19700101-00:00:01", Fields.secToDateTime(1));
  }

  @Test
  void compareBytes_whenDifferentLengths_expectOrdering() {
    byte[] a = new byte[] {1, 2};
    byte[] b = new byte[] {1, 2, 3};
    assertEquals(-1, Fields.compareBytes(a, b));
    assertEquals(1, Fields.compareBytes(b, a));
    assertEquals(0, Fields.compareBytes(a, new byte[] {1, 2}));
  }

  @Test
  void compareBytes_withOffset_whenEqualSegment_expectZero() {
    byte[] a = new byte[] {9, 8, 7, 6, 5};
    byte[] b = new byte[] {0, 7, 6, 5, 4};
    assertEquals(0, Fields.compareBytes(a, b, 2, 1, 3)); // compare [7,6,5]
  }

  @Test
  void byteArrayEqual_whenDifferentLengths_expectFalse() {
    assertFalse(Fields.byteArrayEqual(new byte[] {1}, new byte[] {}));
  }

  @Test
  void byteArrayEqual_whenMismatch_expectFalse() {
    assertFalse(Fields.byteArrayEqual(new byte[] {1, 2, 3}, new byte[] {1, 2, 4}));
  }

  @Test
  void byteArrayEqual_whenOffsetMismatchOrTooShort_expectHandled() {
    byte[] a = new byte[] {1, 2, 3, 4};
    byte[] b = new byte[] {0, 2, 3, 9};
    assertTrue(Fields.byteArrayEqual(a, b, 1, 1, 2)); // [2,3] vs [2,3]
    assertFalse(Fields.byteArrayEqual(a, b, 3, 2, 3)); // out of bounds
  }

  @Test
  void comparator_whenSorted_expectLexicographicOrder() {
    byte[] x = new byte[] {1, 1};
    byte[] y = new byte[] {1, 2};
    byte[] z = new byte[] {2};
    byte[][] arr = new byte[][] {z, x, y};
    Arrays.sort(arr, new Fields.ByteArrayComparator());
    assertArrayEquals(new byte[][] {x, y, z}, arr);
  }

  @Test
  void hashCode_withSubrange_expectSameAsWholeOnSlice() {
    byte[] buf = new byte[] {9, 8, 7, 6, 5, 4, 3, 2};
    int hSub = Fields.hashCode(buf, 2, 4);
    int hWhole = Fields.hashCode(Arrays.copyOfRange(buf, 2, 6));
    assertEquals(hWhole, hSub);
  }

  @Test
  void longHashCode_withSubrange_expectSameAsWholeOnSlice() {
    byte[] buf = new byte[] {1, 2, 3, 4, 5, 6, 7};
    long hSub = Fields.longHashCode(buf, 1, 4);
    long hWhole = Fields.longHashCode(Arrays.copyOfRange(buf, 1, 5));
    assertEquals(hWhole, hSub);
  }

  @Test
  void commaListObject_whenCustomDelimiter_expectJoinedString() {
    Object[] arr = new Object[] {"a", 1, true};
    assertEquals("a|1|true", Fields.commaList(arr, '|'));
    assertEquals("a,1,true", Fields.commaList(arr));
  }

  @Test
  void bytesToShort_whenRoundTrip_expectEqual() {
    short s = (short) 0xA1B2;
    byte[] bytes = Fields.shortToBytes(s);
    assertEquals(s, Fields.bytesToShort(bytes, 0));
  }

  @Test
  void intsToBytes_withOffsetAndLength_expectSubsetEncoded() {
    int[] ints = new int[] {11, 22, 33, 44};
    byte[] subBytes = Fields.intsToBytes(ints, 1, 2); // encode 22,33
    int[] decoded = Fields.bytesToInts(subBytes, 0, subBytes.length);
    assertArrayEquals(new int[] {22, 33}, decoded);
  }

  @Test
  void bytesToInts_whenLengthNotMultipleOfFour_expectException() {
    assertThrows(
        IllegalArgumentException.class, () -> Fields.bytesToInts(new byte[] {1, 2, 3}, 0, 3));
  }

  @Test
  @SuppressWarnings("PointlessArithmeticExpression")
  void parseLong_whenUnitsAndDecimal_expectCorrectValues() {
    assertEquals(2L * (1L << 30), Fields.parseLong("2G"));
    assertEquals(2_000_000_000L, Fields.parseLong("2g"));
    assertEquals(1L * (1L << 30) + (1L << 29), Fields.parseLong("1.5G"));
    assertEquals(1_000L, Fields.parseLong("1E3"));
  }

  @Test
  void parseInt_whenBitsAndBytes_expectDifferentScaling() {
    assertEquals(1, Fields.parseInt("8b")); // 8 bits = 1 byte
    assertEquals(8, Fields.parseInt("8B")); // 8 bytes
    assertEquals(2048, Fields.parseInt("2KiB"));
    assertEquals(2000, Fields.parseInt("2kB"));
  }

  @Test
  void parseInt_withDimensionDuration_expectMillis() {
    assertEquals(90_000, Fields.parseInt("1m30s", network.crypta.config.Dimension.DURATION));
  }

  @Test
  void parseInt_withDimensionOverflow_expectArithmeticException() {
    assertThrows(
        ArithmeticException.class,
        () -> Fields.parseInt("10000000000s", network.crypta.config.Dimension.DURATION));
  }

  @Test
  void trimPerSecond_whenHasQualifiers_expectRemoved() {
    assertEquals("100KiB", Fields.trimPerSecond("100KiB/s"));
    assertEquals("100KiB", Fields.trimPerSecond("100KiB/SEC"));
    assertEquals("100KiB", Fields.trimPerSecond("100KiB/second"));
    assertEquals("100KiB", Fields.trimPerSecond("100KiBps"));
    assertEquals("100KiB", Fields.trimPerSecond("  100KiBps  "));
  }

  @Test
  void longIntShortToString_whenDivisible_expectHumanReadable() {
    assertEquals("2k", Fields.longToString(2000L, false));
    assertEquals("2KiB", Fields.longToString(2048L, true));
    assertEquals("2k", Fields.intToString(2000, false));
    assertEquals("2KiB", Fields.intToString(2048, true));
    assertEquals("2KiB", Fields.shortToString((short) 2048, true));
  }

  @Test
  void doublesBytes_whenRoundTrip_expectEqual() {
    double[] values =
        new double[] {
          0.0, -1.25, Math.PI, Double.longBitsToDouble(0x7ff8000000000000L)
        }; // includes NaN bit pattern
    byte[] bytes = Fields.doublesToBytes(values);
    double[] back = Fields.bytesToDoubles(bytes);
    assertArrayEquals(values, back);
  }

  @Test
  void compareNumeric_whenNaNOrDifferentTypes_expectDeterministicOrdering() {
    assertEquals(0, Fields.compare(Double.NaN, Double.NaN));
    assertEquals(-1, Fields.compare(Double.NaN, 1.0));
    assertEquals(1, Fields.compare(1.0, Double.NaN));
    assertEquals(0, Fields.compare(Float.NaN, Float.NaN));
    assertEquals(-1, Fields.compare(Float.NaN, 1.0f));
    assertEquals(1, Fields.compare(1.0f, Float.NaN));
    assertEquals(1, Fields.compare(2, 1));
    assertEquals(-1, Fields.compare(1L, 2L));
    assertEquals(0, Fields.compare(5, 5));
  }

  @Test
  void compareInstant_whenNulls_expectZeroAndOrdering() {
    Instant now = Instant.now();
    assertEquals(0, Fields.compare(null, null));
    assertEquals(-1, Fields.compare(null, now));
    assertEquals(1, Fields.compare(now, null));
  }

  @Test
  void compareObjectID_whenSameInstance_expectZero() {
    Object ref = new Object();
    assertEquals(0, Fields.compareObjectID(ref, ref));
  }

  @Test
  void copyToArray_whenPartialBuffer_expectRemainingCopied() {
    byte[] data = new byte[] {10, 20, 30, 40, 50};
    ByteBuffer buf = ByteBuffer.wrap(data);
    buf.position(2);
    byte[] out = Fields.copyToArray(buf);
    assertArrayEquals(new byte[] {30, 40, 50}, out);
  }

  @Test
  void parseWithDefaults_whenInvalid_expectDefaultReturned() {
    assertEquals(123L, Fields.parseLong("not-a-long", 123L));
    assertEquals(42, Fields.parseInt("not-an-int", 42));
    assertEquals((short) 7, Fields.parseShort("not-a-short", (short) 7));
  }
}

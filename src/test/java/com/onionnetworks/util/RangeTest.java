package com.onionnetworks.util;

import java.text.ParseException;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class RangeTest {

  @Test
  void constructor_withMinGreaterThanMax_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> new Range(5, 4));
  }

  @Test
  void constructor_withPosInfFalse_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> new Range(1, false));
  }

  @Test
  void constructor_withNegInfFalse_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> new Range(false, 10));
  }

  @Test
  void constructor_withFiniteSingleValue_setsMinMaxAndSize() {
    Range range = new Range(7);

    assertEquals(7, range.getMin());
    assertEquals(7, range.getMax());
    assertEquals(1, range.size());
  }

  @Test
  void size_withInfiniteEndpoints_returnsNegativeOne() {
    Range range = new Range(true, true);

    assertEquals(-1, range.size());
  }

  @Test
  void contains_withinInclusiveBounds_returnsExpectedResults() {
    Range range = new Range(3, 5);

    assertTrue(range.contains(3));
    assertTrue(range.contains(5));
    assertFalse(range.contains(6));
  }

  @Test
  void contains_rangeContainment_respectsBoundaries() {
    Range outer = new Range(1, 10);
    Range inner = new Range(3, 4);

    assertTrue(outer.contains(inner));
    assertFalse(inner.contains(outer));
  }

  @Test
  void contains_infiniteRangeContainsFiniteRange() {
    Range infinite = new Range(true, true);
    Range finite = new Range(-5, 5);

    assertTrue(infinite.contains(finite));
  }

  @Test
  void equals_andHashCode_considerAllFields() {
    Range first = new Range(true, 5);
    Range second = new Range(true, 5);
    Range different = new Range(true, true);

    assertEquals(first, second);
    assertEquals(first.hashCode(), second.hashCode());
    assertNotEquals(first, different);
  }

  @ParameterizedTest
  @MethodSource("toStringCases")
  void toString_formatsRangesCorrectly(Range range, String expected) {
    assertEquals(expected, range.toString());
  }

  private static Stream<Arguments> toStringCases() {
    return Stream.of(
        Arguments.of(new Range(5), "5"),
        Arguments.of(new Range(1, 3), "1-3"),
        Arguments.of(new Range(true, 4), "(-4"),
        Arguments.of(new Range(10, true), "10-)"),
        Arguments.of(new Range(true, true), "(-)"));
  }

  @ParameterizedTest
  @MethodSource("parseCases")
  void parse_validStrings_createExpectedRanges(
      String input, long expectedMin, long expectedMax, boolean negInf, boolean posInf)
      throws ParseException {
    Range range = Range.parse(input);

    assertEquals(expectedMin, range.getMin());
    assertEquals(expectedMax, range.getMax());
    assertEquals(negInf, range.isMinNegInf());
    assertEquals(posInf, range.isMaxPosInf());
  }

  private static Stream<Arguments> parseCases() {
    return Stream.of(
        Arguments.of("11", 11L, 11L, false, false),
        Arguments.of("-6", -6L, -6L, false, false),
        Arguments.of("10-20", 10L, 20L, false, false),
        Arguments.of("-10--5", -10L, -5L, false, false),
        Arguments.of("(-20", Long.MIN_VALUE, 20L, true, false),
        Arguments.of("30-)", 30L, Long.MAX_VALUE, false, true),
        Arguments.of("(-)", Long.MIN_VALUE, Long.MAX_VALUE, true, true));
  }

  @Test
  void parse_invalidString_throwsParseException() {
    assertThrows(ParseException.class, () -> Range.parse("abc"));
    assertThrows(ParseException.class, () -> Range.parse("10-"));
  }
}

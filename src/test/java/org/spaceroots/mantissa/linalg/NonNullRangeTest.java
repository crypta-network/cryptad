package org.spaceroots.mantissa.linalg;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;

import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("java:S100")
class NonNullRangeTest {

  @Test
  @DisplayName("constructor sets provided bounds")
  void constructor_whenGivenBounds_setsFields() {
    NonNullRange range = new NonNullRange(2, 7);

    assertEquals(2, range.begin);
    assertEquals(7, range.end);
  }

  @Test
  @DisplayName("copy constructor duplicates values without aliasing")
  void copyConstructor_whenRangeProvided_copiesValues() {
    NonNullRange original = new NonNullRange(1, 4);

    NonNullRange copy = new NonNullRange(original);

    assertNotSame(original, copy);
    assertEquals(original.begin, copy.begin);
    assertEquals(original.end, copy.end);
  }

  @ParameterizedTest(name = "intersection of [{0},{1}) and [{2},{3}) -> [{4},{5})")
  @MethodSource("intersectionCases")
  void intersection_whenRangesGiven_returnsExpectedIntersection(
      int firstBegin,
      int firstEnd,
      int secondBegin,
      int secondEnd,
      int expectedBegin,
      int expectedEnd) {
    NonNullRange first = new NonNullRange(firstBegin, firstEnd);
    NonNullRange second = new NonNullRange(secondBegin, secondEnd);

    NonNullRange result = NonNullRange.intersection(first, second);

    assertEquals(expectedBegin, result.begin);
    assertEquals(expectedEnd, result.end);
  }

  private static Stream<org.junit.jupiter.params.provider.Arguments> intersectionCases() {
    return Stream.of(
        org.junit.jupiter.params.provider.Arguments.of(0, 5, 2, 7, 2, 5), // partial overlap
        org.junit.jupiter.params.provider.Arguments.of(0, 3, 3, 6, 3, 3), // touching edges
        org.junit.jupiter.params.provider.Arguments.of(
            0, 2, 3, 5, 3, 2), // disjoint produces empty range
        org.junit.jupiter.params.provider.Arguments.of(
            1, 6, 2, 4, 2, 4)); // second fully inside first
  }

  @ParameterizedTest(name = "reunion of [{0},{1}) and [{2},{3}) -> [{4},{5})")
  @MethodSource("reunionCases")
  void reunion_whenRangesGiven_returnsSmallestEnclosingRange(
      int firstBegin,
      int firstEnd,
      int secondBegin,
      int secondEnd,
      int expectedBegin,
      int expectedEnd) {
    NonNullRange first = new NonNullRange(firstBegin, firstEnd);
    NonNullRange second = new NonNullRange(secondBegin, secondEnd);

    NonNullRange result = NonNullRange.reunion(first, second);

    assertEquals(expectedBegin, result.begin);
    assertEquals(expectedEnd, result.end);
  }

  private static Stream<org.junit.jupiter.params.provider.Arguments> reunionCases() {
    return Stream.of(
        org.junit.jupiter.params.provider.Arguments.of(0, 5, 2, 7, 0, 7), // partial overlap
        org.junit.jupiter.params.provider.Arguments.of(0, 3, 3, 6, 0, 6), // touching edges
        org.junit.jupiter.params.provider.Arguments.of(0, 2, 3, 5, 0, 5), // disjoint
        org.junit.jupiter.params.provider.Arguments.of(
            1, 6, 2, 4, 1, 6)); // one range contains the other
  }
}

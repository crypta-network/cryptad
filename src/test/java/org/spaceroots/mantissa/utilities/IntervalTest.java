package org.spaceroots.mantissa.utilities;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class IntervalTest {

  @Test
  void constructor_default_expectZeroBoundsAndLength() {
    Interval interval = new Interval();

    assertAll(
        () -> assertEquals(0.0, interval.getInf()),
        () -> assertEquals(0.0, interval.getSup()),
        () -> assertEquals(0.0, interval.getLength()));
  }

  @ParameterizedTest
  @CsvSource({
    "1.0,2.0,1.0,2.0",
    "2.0,1.0,1.0,2.0",
    "-5.0,-2.0,-5.0,-2.0",
    "-2.0,-5.0,-5.0,-2.0",
    "-1.0,3.0,-1.0,3.0"
  })
  void constructor_whenBoundsUnordered_expectOrderedInterval(
      double a, double b, double expectedInf, double expectedSup) {
    Interval interval = new Interval(a, b);

    assertAll(
        () -> assertEquals(expectedInf, interval.getInf()),
        () -> assertEquals(expectedSup, interval.getSup()),
        () -> assertEquals(expectedSup - expectedInf, interval.getLength()));
  }

  @Test
  void constructor_copy_expectIndependentCopyWithSameValues() {
    Interval original = new Interval(-2.0, 5.0);
    Interval copy = new Interval(original);

    assertAll(
        () -> assertEquals(original.getInf(), copy.getInf()),
        () -> assertEquals(original.getSup(), copy.getSup()),
        () -> assertEquals(original.getLength(), copy.getLength()));
  }

  @ParameterizedTest
  @CsvSource({
    "-1.0,1.0,-1.0,true",
    "-1.0,1.0,1.0,true",
    "-1.0,1.0,0.0,true",
    "-1.0,1.0,-1.0001,false",
    "-1.0,1.0,1.0001,false"
  })
  void contains_whenPointProvided_expectCorrectInclusion(
      double inf, double sup, double x, boolean expected) {
    Interval interval = new Interval(inf, sup);

    boolean result = interval.contains(x);

    assertEquals(expected, result);
  }

  @Test
  void contains_whenPointIsNaN_expectFalse() {
    Interval interval = new Interval(-1.0, 1.0);

    boolean result = interval.contains(Double.NaN);

    assertFalse(result);
  }

  @Test
  void contains_whenIntervalFullyInside_expectTrue() {
    Interval outer = new Interval(-10.0, 10.0);
    Interval inner = new Interval(-2.0, 3.0);

    boolean result = outer.contains(inner);

    assertTrue(result);
  }

  @Test
  void contains_whenIntervalTouchesBounds_expectTrue() {
    Interval outer = new Interval(0.0, 5.0);
    Interval touching = new Interval(0.0, 5.0);

    boolean result = outer.contains(touching);

    assertTrue(result);
  }

  @Test
  void contains_whenIntervalPartiallyOutside_expectFalse() {
    Interval outer = new Interval(0.0, 5.0);
    Interval other = new Interval(-1.0, 3.0);

    boolean result = outer.contains(other);

    assertFalse(result);
  }

  @Test
  void intersects_whenOverlapping_expectTrue() {
    Interval i1 = new Interval(0.0, 5.0);
    Interval i2 = new Interval(3.0, 7.0);

    boolean result = i1.intersects(i2);

    assertTrue(result);
  }

  @Test
  void intersects_whenDisjoint_expectFalse() {
    Interval i1 = new Interval(0.0, 2.0);
    Interval i2 = new Interval(3.0, 4.0);

    boolean result = i1.intersects(i2);

    assertFalse(result);
  }

  @Test
  void intersects_whenTouchingAtSinglePoint_expectTrue() {
    Interval i1 = new Interval(0.0, 2.0);
    Interval i2 = new Interval(2.0, 3.0);

    boolean result = i1.intersects(i2);

    assertTrue(result);
  }

  @Test
  void intersects_whenOtherHasNaNBound_expectFalse() {
    Interval i1 = new Interval(0.0, 2.0);
    Interval i2 = new Interval(Double.NaN, 1.0);

    boolean result = i1.intersects(i2);

    assertFalse(result);
  }

  @Test
  void addToSelf_whenOverlapping_expectExpandedBounds() {
    Interval interval = new Interval(0.0, 5.0);
    Interval toAdd = new Interval(3.0, 7.0);

    interval.addToSelf(toAdd);

    assertAll(
        () -> assertEquals(0.0, interval.getInf()),
        () -> assertEquals(7.0, interval.getSup()),
        () -> assertEquals(7.0, interval.getLength()));
  }

  @Test
  void addToSelf_whenDisjoint_expectHoleFilled() {
    Interval interval = new Interval(0.0, 1.0);
    Interval toAdd = new Interval(3.0, 4.0);

    interval.addToSelf(toAdd);

    assertAll(
        () -> assertEquals(0.0, interval.getInf()),
        () -> assertEquals(4.0, interval.getSup()),
        () -> assertEquals(4.0, interval.getLength()));
  }

  @Test
  void add_whenCalled_expectNewIntervalAndInputsUnchanged() {
    Interval i1 = new Interval(0.0, 1.0);
    Interval i2 = new Interval(3.0, 4.0);

    Interval result = Interval.add(i1, i2);

    assertAll(
        () -> assertEquals(0.0, result.getInf()),
        () -> assertEquals(4.0, result.getSup()),
        () -> assertEquals(0.0, i1.getInf()),
        () -> assertEquals(1.0, i1.getSup()),
        () -> assertEquals(3.0, i2.getInf()),
        () -> assertEquals(4.0, i2.getSup()));
  }

  @Test
  void intersection_whenOverlapping_expectCorrectIntersection() {
    Interval i1 = new Interval(0.0, 5.0);
    Interval i2 = new Interval(3.0, 7.0);

    Interval result = Interval.intersection(i1, i2);

    assertAll(
        () -> assertEquals(3.0, result.getInf()),
        () -> assertEquals(5.0, result.getSup()),
        () -> assertEquals(2.0, result.getLength()));
  }

  @Test
  void intersection_whenDisjoint_expectEmptyIntersectionAtNearestPoint() {
    Interval i1 = new Interval(0.0, 1.0);
    Interval i2 = new Interval(3.0, 4.0);

    Interval result = Interval.intersection(i1, i2);

    assertAll(
        () -> assertEquals(3.0, result.getInf()),
        () -> assertEquals(3.0, result.getSup()),
        () -> assertEquals(0.0, result.getLength()));
  }

  @Test
  void intersectSelf_whenOverlapping_expectReducedBounds() {
    Interval interval = new Interval(0.0, 5.0);
    Interval other = new Interval(3.0, 7.0);

    interval.intersectSelf(other);

    assertAll(
        () -> assertEquals(3.0, interval.getInf()),
        () -> assertEquals(5.0, interval.getSup()),
        () -> assertEquals(2.0, interval.getLength()));
  }

  @Test
  void intersectSelf_whenDisjoint_expectCollapsedToPoint() {
    Interval interval = new Interval(0.0, 1.0);
    Interval other = new Interval(3.0, 4.0);

    interval.intersectSelf(other);

    assertAll(
        () -> assertEquals(3.0, interval.getInf()),
        () -> assertEquals(3.0, interval.getSup()),
        () -> assertEquals(0.0, interval.getLength()));
  }

  @Test
  void getLength_whenBoundsIncludeInfinity_expectInfinityLength() {
    Interval interval = new Interval(Double.NEGATIVE_INFINITY, Double.POSITIVE_INFINITY);

    double length = interval.getLength();

    assertEquals(Double.POSITIVE_INFINITY, length);
  }

  @Test
  void staticAdd_whenOneInputIsSameObject_expectResultNotAliased() {
    Interval interval = new Interval(0.0, 1.0);

    Interval result = Interval.add(interval, interval);

    assertAll(
        () -> assertEquals(0.0, result.getInf()),
        () -> assertEquals(1.0, result.getSup()),
        () -> assertNotSame(interval, result));
  }
}

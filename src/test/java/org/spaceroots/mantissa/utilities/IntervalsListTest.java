package org.spaceroots.mantissa.utilities;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class IntervalsListTest {

  @Test
  void constructor_whenNoArgs_expectEmptyListWithNaNBounds() {
    // Arrange
    IntervalsList list = new IntervalsList();

    // Act + Assert
    assertTrue(list.isEmpty());
    assertFalse(list.isConnex());
    assertEquals(0, list.getSize());
    assertTrue(Double.isNaN(list.getInf()));
    assertTrue(Double.isNaN(list.getSup()));
    assertFalse(list.contains(0.0));
    assertFalse(list.contains(Double.NaN));
    assertFalse(list.contains(new Interval(0.0, 1.0)));
    assertFalse(list.intersects(new Interval(0.0, 1.0)));
  }

  @ParameterizedTest
  @MethodSource("singleIntervalConstructorCases")
  void constructor_whenTwoDoubles_expectSingleNormalizedInterval(
      double a, double b, double expectedInf, double expectedSup) {
    // Arrange
    IntervalsList list = new IntervalsList(a, b);

    // Act + Assert
    assertFalse(list.isEmpty());
    assertTrue(list.isConnex());
    assertEquals(1, list.getSize());
    assertEquals(expectedInf, list.getInf(), 0.0);
    assertEquals(expectedSup, list.getSup(), 0.0);
    assertEquals(expectedInf, list.getInterval(0).getInf(), 0.0);
    assertEquals(expectedSup, list.getInterval(0).getSup(), 0.0);
  }

  static Stream<Arguments> singleIntervalConstructorCases() {
    return Stream.of(
        Arguments.of(0.0, 1.0, 0.0, 1.0),
        Arguments.of(1.0, 0.0, 0.0, 1.0),
        Arguments.of(-2.0, -5.0, -5.0, -2.0),
        Arguments.of(3.5, 3.5, 3.5, 3.5));
  }

  @Test
  void constructor_whenIntervalProvided_expectSameInstanceStored() {
    // Arrange
    Interval interval = new Interval(2.0, 3.0);

    // Act
    IntervalsList list = new IntervalsList(interval);

    // Assert
    assertSame(interval, list.getInterval(0));
    assertTrue(list.contains(new Interval(2.1, 2.9)));
  }

  @Test
  void constructor_whenTwoIntervalsOverlap_expectMergedSingleInterval() {
    // Arrange
    Interval i1 = new Interval(0.0, 2.0);
    Interval i2 = new Interval(1.0, 3.0);

    // Act
    IntervalsList list = new IntervalsList(i1, i2);

    // Assert
    assertIntervals(list, 0.0, 3.0);
  }

  @Test
  void constructor_whenTwoIntervalsAreDisjoint_expectSortedOrder() {
    // Arrange
    Interval i1 = new Interval(10.0, 11.0);
    Interval i2 = new Interval(0.0, 1.0);

    // Act
    IntervalsList list = new IntervalsList(i1, i2);

    // Assert
    assertIntervals(list, 0.0, 1.0, 10.0, 11.0);
  }

  @Test
  void copyConstructor_whenCopied_expectDeepCopyOfIntervals() {
    // Arrange
    Interval originalInterval = new Interval(0.0, 1.0);
    IntervalsList original = new IntervalsList(originalInterval);

    // Act
    IntervalsList copy = new IntervalsList(original);
    originalInterval.addToSelf(new Interval(10.0, 11.0));

    // Assert
    assertIntervals(copy, 0.0, 1.0);
    assertNotSame(original.getInterval(0), copy.getInterval(0));
  }

  @Test
  void getInterval_whenIndexOutOfBounds_expectException() {
    // Arrange
    IntervalsList list = new IntervalsList(0.0, 1.0);

    // Act + Assert
    assertThrows(IndexOutOfBoundsException.class, () -> list.getInterval(-1));
    assertThrows(IndexOutOfBoundsException.class, () -> list.getInterval(1));
  }

  @ParameterizedTest
  @ValueSource(doubles = {0.0, 1.0, 3.0, 4.0})
  void contains_whenPointWithinEndpoints_expectTrue(double x) {
    // Arrange
    IntervalsList list = new IntervalsList(new Interval(0.0, 1.0), new Interval(3.0, 4.0));

    // Act + Assert
    assertTrue(list.contains(x));
  }

  @Test
  void contains_whenPointIsInHole_expectFalse() {
    // Arrange
    IntervalsList list = new IntervalsList(new Interval(0.0, 1.0), new Interval(3.0, 4.0));

    // Act + Assert
    assertFalse(list.contains(2.0));
  }

  @Test
  void contains_whenPointIsNaN_expectFalse() {
    // Arrange
    IntervalsList list = new IntervalsList(0.0, 1.0);

    // Act + Assert
    assertFalse(list.contains(Double.NaN));
  }

  @Test
  void contains_whenIntervalFullyContained_expectTrue() {
    // Arrange
    IntervalsList list = new IntervalsList(new Interval(0.0, 1.0), new Interval(3.0, 4.0));

    // Act + Assert
    assertTrue(list.contains(new Interval(3.1, 3.9)));
  }

  @Test
  void contains_whenIntervalSpansHole_expectFalse() {
    // Arrange
    IntervalsList list = new IntervalsList(new Interval(0.0, 1.0), new Interval(3.0, 4.0));

    // Act + Assert
    assertFalse(list.contains(new Interval(0.5, 3.5)));
  }

  @Test
  void intersects_whenIntervalTouchesOrOverlapsAnyLocalInterval_expectTrue() {
    // Arrange
    IntervalsList list = new IntervalsList(new Interval(0.0, 1.0), new Interval(3.0, 4.0));

    // Act + Assert
    assertTrue(list.intersects(new Interval(1.0, 2.0)));
    assertTrue(list.intersects(new Interval(2.5, 3.0)));
    assertTrue(list.intersects(new Interval(0.5, 0.6)));
  }

  @Test
  void intersects_whenIntervalIsInHole_expectFalse() {
    // Arrange
    IntervalsList list = new IntervalsList(new Interval(0.0, 1.0), new Interval(3.0, 4.0));

    // Act + Assert
    assertFalse(list.intersects(new Interval(1.5, 2.5)));
  }

  @Test
  void addToSelf_whenDisjointIntervals_expectInsertionInOrder() {
    // Arrange
    IntervalsList list = new IntervalsList(5.0, 6.0);

    // Act
    list.addToSelf(new Interval(0.0, 1.0));
    list.addToSelf(new Interval(10.0, 11.0));

    // Assert
    assertIntervals(list, 0.0, 1.0, 5.0, 6.0, 10.0, 11.0);
  }

  @Test
  void addToSelf_whenOverlappingExistingInterval_expectMerge() {
    // Arrange
    IntervalsList list = new IntervalsList(0.0, 2.0);

    // Act
    list.addToSelf(new Interval(1.0, 3.0));

    // Assert
    assertIntervals(list, 0.0, 3.0);
  }

  @Test
  void addToSelf_whenAddedIntervalOverlapsTwoIntervals_expectMergeAndFillHole() {
    // Arrange
    IntervalsList list = new IntervalsList(new Interval(0.0, 1.0), new Interval(4.0, 5.0));

    // Act
    list.addToSelf(new Interval(0.5, 4.5));

    // Assert
    assertIntervals(list, 0.0, 5.0);
  }

  @Test
  void addToSelf_whenAddedIntervalFitsBetweenTwoIntervals_expectThreeIntervals() {
    // Arrange
    IntervalsList list = new IntervalsList(new Interval(0.0, 1.0), new Interval(4.0, 5.0));

    // Act
    list.addToSelf(new Interval(2.0, 3.0));

    // Assert
    assertIntervals(list, 0.0, 1.0, 2.0, 3.0, 4.0, 5.0);
  }

  @Test
  void add_whenCalled_expectNewListAndOriginalUnchanged() {
    // Arrange
    IntervalsList original = new IntervalsList(0.0, 1.0);

    // Act
    IntervalsList merged = IntervalsList.add(original, new Interval(2.0, 3.0));

    // Assert
    assertIntervals(original, 0.0, 1.0);
    assertIntervals(merged, 0.0, 1.0, 2.0, 3.0);
  }

  @Test
  void add_whenListToSelf_expectUnionAcrossAllIntervals() {
    // Arrange
    IntervalsList list1 = new IntervalsList(new Interval(0.0, 1.0), new Interval(4.0, 5.0));
    IntervalsList list2 = new IntervalsList(new Interval(-2.0, -1.0), new Interval(0.5, 4.5));

    // Act
    list1.addToSelf(list2);

    // Assert
    assertIntervals(list1, -2.0, -1.0, 0.0, 5.0);
  }

  @Test
  void add_whenStaticUnion_expectNewListAndInputsUnchanged() {
    // Arrange
    IntervalsList list1 = new IntervalsList(0.0, 1.0);
    IntervalsList list2 = new IntervalsList(3.0, 4.0);

    // Act
    IntervalsList union = IntervalsList.add(list1, list2);

    // Assert
    assertIntervals(list1, 0.0, 1.0);
    assertIntervals(list2, 3.0, 4.0);
    assertIntervals(union, 0.0, 1.0, 3.0, 4.0);
  }

  @Test
  void subtractFromSelf_whenSubtractInsideSingleInterval_expectSplitAndKeepEndpoints() {
    // Arrange
    IntervalsList list = new IntervalsList(0.0, 10.0);

    // Act
    list.subtractFromSelf(new Interval(2.0, 3.0));

    // Assert
    assertIntervals(list, 0.0, 2.0, 3.0, 10.0);
    assertTrue(list.contains(2.0));
    assertTrue(list.contains(3.0));
    assertFalse(list.contains(2.5));
  }

  @Test
  void subtractFromSelf_whenSubtractDisjointInterval_expectUnchanged() {
    // Arrange
    IntervalsList list = new IntervalsList(0.0, 1.0);

    // Act
    list.subtractFromSelf(new Interval(2.0, 3.0));

    // Assert
    assertIntervals(list, 0.0, 1.0);
  }

  @Test
  void subtractFromSelf_whenSubtractCoversAll_expectEmpty() {
    // Arrange
    IntervalsList list = new IntervalsList(0.0, 1.0);

    // Act
    list.subtractFromSelf(new Interval(-10.0, 10.0));

    // Assert
    assertTrue(list.isEmpty());
  }

  @Test
  void subtractFromSelf_whenCalledOnEmptyList_expectStillEmpty() {
    // Arrange
    IntervalsList list = new IntervalsList();

    // Act
    list.subtractFromSelf(new Interval(-10.0, 10.0));

    // Assert
    assertTrue(list.isEmpty());
    assertEquals(0, list.getSize());
  }

  @Test
  void subtract_whenStaticSubtract_expectNewListAndOriginalUnchanged() {
    // Arrange
    IntervalsList original = new IntervalsList(0.0, 10.0);

    // Act
    IntervalsList result = IntervalsList.subtract(original, new Interval(2.0, 3.0));

    // Assert
    assertIntervals(original, 0.0, 10.0);
    assertIntervals(result, 0.0, 2.0, 3.0, 10.0);
  }

  @Test
  void subtractFromSelf_whenSubtractList_expectSequentialSubtractions() {
    // Arrange
    IntervalsList list = new IntervalsList(0.0, 10.0);
    IntervalsList toRemove = new IntervalsList(new Interval(2.0, 3.0), new Interval(6.0, 7.0));

    // Act
    list.subtractFromSelf(toRemove);

    // Assert
    assertIntervals(list, 0.0, 2.0, 3.0, 6.0, 7.0, 10.0);
  }

  @Test
  void intersection_whenIntersectWithInterval_expectOnlyOverlappingParts() {
    // Arrange
    IntervalsList list = new IntervalsList(new Interval(0.0, 1.0), new Interval(3.0, 4.0));

    // Act
    list.intersectSelf(new Interval(0.5, 3.5));

    // Assert
    assertIntervals(list, 0.5, 1.0, 3.0, 3.5);
  }

  @Test
  void intersection_whenStaticIntersectionWithInterval_expectNewListAndOriginalUnchanged() {
    // Arrange
    IntervalsList original = new IntervalsList(new Interval(0.0, 1.0), new Interval(3.0, 4.0));

    // Act
    IntervalsList intersection = IntervalsList.intersection(original, new Interval(0.5, 3.5));

    // Assert
    assertIntervals(original, 0.0, 1.0, 3.0, 4.0);
    assertIntervals(intersection, 0.5, 1.0, 3.0, 3.5);
  }

  @Test
  void intersection_whenIntersectTwoLists_expectCorrectResult() {
    // Arrange
    IntervalsList list1 = new IntervalsList(new Interval(0.0, 2.0), new Interval(4.0, 6.0));
    IntervalsList list2 = new IntervalsList(new Interval(1.0, 5.0), new Interval(7.0, 8.0));

    // Act
    IntervalsList intersection = IntervalsList.intersection(list1, list2);

    // Assert
    assertIntervals(intersection, 1.0, 2.0, 4.0, 5.0);
  }

  @Test
  void intersectSelf_whenIntersectTwoLists_expectInPlaceIntersection() {
    // Arrange
    IntervalsList list1 = new IntervalsList(new Interval(0.0, 2.0), new Interval(4.0, 6.0));
    IntervalsList list2 = new IntervalsList(new Interval(1.0, 5.0), new Interval(7.0, 8.0));

    // Act
    list1.intersectSelf(list2);

    // Assert
    assertIntervals(list1, 1.0, 2.0, 4.0, 5.0);
  }

  @Test
  void contains_whenIntervalIsMocked_expectDelegatedResult() {
    // Arrange
    Interval interval = mock(Interval.class);
    when(interval.contains(123.0)).thenReturn(true);
    when(interval.contains(124.0)).thenReturn(false);
    IntervalsList list = new IntervalsList(interval);

    // Act + Assert
    assertTrue(list.contains(123.0));
    assertFalse(list.contains(124.0));
  }

  private static void assertIntervals(IntervalsList list, double... bounds) {
    assertEquals(0, bounds.length % 2);
    assertEquals(bounds.length / 2, list.getSize());

    for (int i = 0; i < bounds.length; i += 2) {
      Interval interval = list.getInterval(i / 2);
      assertEquals(bounds[i], interval.getInf(), 0.0);
      assertEquals(bounds[i + 1], interval.getSup(), 0.0);
    }

    if (bounds.length == 0) {
      assertTrue(Double.isNaN(list.getInf()));
      assertTrue(Double.isNaN(list.getSup()));
    } else {
      assertEquals(bounds[0], list.getInf(), 0.0);
      assertEquals(bounds[bounds.length - 1], list.getSup(), 0.0);
    }
  }
}

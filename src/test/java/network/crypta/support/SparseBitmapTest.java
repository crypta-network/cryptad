package network.crypta.support;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class SparseBitmapTest {

  @Test
  void add_whenDisjointAndAdjacent_expectMergeAndContainment() {
    // Arrange
    SparseBitmap s = new SparseBitmap();

    // Act
    s.add(0, 1);
    s.add(3, 3);
    s.add(0, 5); // merges 0-1,3-3 into 0-5
    s.add(10, 15);

    // Assert
    assertTrue(s.contains(0, 5));
    assertTrue(s.contains(2, 2)); // covered after merge into 0-5
    assertTrue(s.contains(10, 15));
    // invalid range
    assertThrows(IllegalArgumentException.class, () -> s.add(5, 0));
    assertTrue(s.contains(0, 5));
    assertTrue(s.contains(10, 15));
  }

  @Test
  void clear_whenCalled_expectEmpty() {
    // Arrange
    SparseBitmap s = new SparseBitmap();
    s.add(0, 2);

    // Act
    s.clear();

    // Assert
    assertFalse(s.contains(1, 1));
    assertTrue(s.isEmpty());
  }

  @Test
  void remove_whenOverlappingStartEndAndMiddle_expectSplitAndCleanup() {
    // Arrange
    SparseBitmap s = new SparseBitmap();
    s.add(0, 4);
    s.add(10, 14);

    // Act & Assert — remove beginning of second range
    s.remove(10, 11);
    assertTrue(s.contains(0, 4));
    assertFalse(s.contains(5, 11));
    assertTrue(s.contains(12, 14));

    // Act & Assert — remove end of first range
    s.remove(4, 4);
    assertTrue(s.contains(0, 3));
    assertFalse(s.contains(4, 11));
    assertTrue(s.contains(12, 14));

    // Act & Assert — removing an empty/covered gap has no effect
    s.remove(4, 11);
    assertTrue(s.contains(0, 3));
    assertFalse(s.contains(4, 11));
    assertTrue(s.contains(12, 14));

    // Act & Assert — remove across both ranges, splitting appropriately
    s.remove(3, 12);
    assertTrue(s.contains(0, 2));
    assertFalse(s.contains(3, 12));
    assertTrue(s.contains(13, 14));
  }

  @Test
  void remove_whenInvalidRange_expectIllegalArgument() {
    // Arrange
    SparseBitmap s = new SparseBitmap();
    s.add(0, 2);

    // Act & Assert
    assertThrows(IllegalArgumentException.class, () -> s.remove(5, 2));
  }

  @Test
  void notOverlapping_whenVariedSubranges_expectConsistentCountsAndInvariants() {
    // The nested loop explores many subranges deterministically
    for (int a = 0; a <= 20; a++) {
      for (int b = a; b <= 20; b++) {
        // Arrange
        SparseBitmap s = new SparseBitmap();
        s.add(-10, -1);
        s.add(3, 10);
        s.add(12, 12);
        s.add(14, 16);
        s.add(17, 17);
        s.add(19, 22);

        // Act
        assertEquals(6, s.notOverlapping(-10, 22));
        final int notOverlapping = s.notOverlapping(a, b);
        final int width = b - a + 1;
        final int overlapping = width - notOverlapping;

        // Assert
        assertEquals((notOverlapping == 0), s.contains(a, b));

        s.remove(a, b);
        assertFalse(s.contains(a, b));
        assertEquals(width, s.notOverlapping(a, b));
        assertEquals(6 + overlapping, s.notOverlapping(-10, 22));

        // Removing again should be idempotent
        s.remove(a, b);
        assertFalse(s.contains(a, b));
        assertEquals(width, s.notOverlapping(a, b));
        assertEquals(6 + overlapping, s.notOverlapping(-10, 22));

        // Adding back makes subrange fully present
        s.add(a, b);
        assertTrue(s.contains(a, b));
        assertEquals(0, s.notOverlapping(a, b));
        assertEquals(6 - notOverlapping, s.notOverlapping(-10, 22));

        // Adding again merges to same state
        s.add(a, b);
        assertTrue(s.contains(a, b));
        assertEquals(0, s.notOverlapping(a, b));
        assertEquals(6 - notOverlapping, s.notOverlapping(-10, 22));
      }
    }
  }

  @Test
  void contains_whenStartGreaterThanEnd_expectIllegalArgument() {
    // Arrange
    SparseBitmap s = new SparseBitmap();

    // Act & Assert
    assertThrows(IllegalArgumentException.class, () -> s.contains(2, 1));
  }

  @Test
  void iterator_whenAddingBackwardsOrTouching_expectSingleMergedRange() {
    // Arrange
    SparseBitmap s = new SparseBitmap();
    s.add(5, 10);
    s.add(0, 5);

    // Act
    Iterator<int[]> it = s.iterator();

    // Assert
    assertTrue(it.hasNext());
    int[] range = it.next();
    assertEquals(0, range[0]);
    assertEquals(10, range[1]);
    assertFalse(it.hasNext());
  }

  @Test
  void iterator_whenMiddleRangeCompletesMerge_expectSingleMergedRange() {
    // Arrange
    SparseBitmap s = new SparseBitmap();
    s.add(10, 15);
    s.add(0, 5);
    s.add(5, 10);

    // Act
    Iterator<int[]> it = s.iterator();

    // Assert
    assertTrue(it.hasNext());
    int[] range = it.next();
    assertEquals(0, range[0]);
    assertEquals(15, range[1]);
    assertFalse(it.hasNext());
  }

  @Test
  void iterator_whenAdjacentRanges_expectTheyMerge() {
    // Arrange
    SparseBitmap s = new SparseBitmap();
    s.add(10, 14);
    s.add(0, 4);
    s.add(5, 9);

    // Act
    Iterator<int[]> it = s.iterator();

    // Assert
    assertTrue(it.hasNext());
    int[] range = it.next();
    assertEquals(0, range[0]);
    assertEquals(14, range[1]);
    assertFalse(it.hasNext());
  }

  @Test
  void iterator_removeEachRange_expectBitmapEmptied() {
    // Arrange
    SparseBitmap s = new SparseBitmap();
    s.add(0, 1);
    s.add(3, 3);
    s.add(5, 7);

    // Act
    List<int[]> seen = new ArrayList<>();
    Iterator<int[]> it = s.iterator();
    while (it.hasNext()) {
      int[] r = it.next();
      seen.add(new int[] {r[0], r[1]});
      it.remove(); // remove current range
    }

    // Assert: all removed
    assertTrue(s.isEmpty());
    assertEquals(3, seen.size());
    assertEquals(0, seen.get(0)[0]);
    assertEquals(1, seen.get(0)[1]);
    assertEquals(3, seen.get(1)[0]);
    assertEquals(3, seen.get(1)[1]);
    assertEquals(5, seen.get(2)[0]);
    assertEquals(7, seen.get(2)[1]);

    // Also verify calling remove on an exhausted iterator does not appear here; behavior is
    // undefined
    assertDoesNotThrow(
        () -> {
          // nothing — just ensure we reached here without exceptions
        });
  }

  @Test
  void iterator_returnedArrayIsDefensiveCopy_expectToStringUnaffected() {
    // Arrange
    SparseBitmap s = new SparseBitmap();
    s.add(1, 2);

    // Act
    int[] r = s.iterator().next();
    r[0] = 100;
    r[1] = -42;

    // Assert: internal state not impacted by external mutation
    assertEquals("1->2", s.toString());
  }

  @Test
  void toString_whenMultipleRanges_expectSortedCommaSeparated() {
    // Arrange
    SparseBitmap s = new SparseBitmap();
    s.add(2, 3);
    s.add(0, 0);

    // Act
    String desc = s.toString();

    // Assert
    assertEquals("0->0, 2->3", desc);
  }

  @Test
  void copyConstructor_whenMutatingCopy_expectOriginalUnaffected() {
    // Arrange
    SparseBitmap original = new SparseBitmap();
    original.add(0, 0);
    original.add(10, 12);

    // Act
    SparseBitmap copy = new SparseBitmap(original);
    copy.add(5, 6);
    copy.remove(10, 11);

    // Assert
    assertTrue(original.contains(0, 0));
    assertTrue(original.contains(10, 12));
    assertFalse(original.contains(5, 6));
    assertTrue(copy.contains(0, 0));
    assertTrue(copy.contains(5, 6));
    assertFalse(copy.contains(10, 11));
    assertTrue(copy.contains(12, 12));
  }

  @Test
  void contains_whenExactEdges_expectTrueAndOutside_expectFalse() {
    // Arrange
    SparseBitmap s = new SparseBitmap();
    s.add(5, 10);

    // Assert edges and outside
    assertTrue(s.contains(5, 5));
    assertTrue(s.contains(10, 10));
    assertFalse(s.contains(4, 10));
    assertFalse(s.contains(5, 11));
  }
}

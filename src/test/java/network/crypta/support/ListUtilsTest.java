package network.crypta.support;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/** Test case for {@link ListUtils} class. */
@SuppressWarnings("java:S100") // Allow descriptive test method names with underscores
class ListUtilsTest {

  @Test
  void removeBySwapLastObject_whenElementAbsent_expectFalseAndNoChange() {
    // Arrange
    ArrayList<Integer> list = new ArrayList<>();
    for (int i = 0; i < 10; i++) list.add(i);
    int oldSize = list.size();

    // Act
    boolean removed = ListUtils.removeBySwapLast(list, Integer.valueOf(oldSize + 1));

    // Assert
    assertFalse(removed);
    assertEquals(oldSize, list.size());
    for (int i = 0; i < list.size(); i++) {
      assertEquals(Integer.valueOf(i), list.get(i));
    }
  }

  @Test
  void removeBySwapLastObject_whenRemovingLast_expectRemovedAndSizeDecrement() {
    // Arrange
    ArrayList<Integer> list = new ArrayList<>();
    for (int i = 0; i < 10; i++) list.add(i);
    int oldSize = list.size();
    Integer oldTop = list.get(oldSize - 1);

    // Act
    boolean removed = ListUtils.removeBySwapLast(list, oldTop);

    // Assert
    assertTrue(removed);
    assertEquals(oldSize - 1, list.size());
    assertFalse(list.contains(oldTop));
    for (int i = 0; i < list.size(); i++) {
      assertEquals(Integer.valueOf(i), list.get(i));
    }
  }

  @Test
  void removeBySwapLastObject_whenRemovingFirst_expectMovesLastIntoIndexZero() {
    // Arrange
    ArrayList<Integer> list = new ArrayList<>();
    for (int i = 0; i < 10; i++) list.add(i);
    int oldSize = list.size();
    Integer oldFirst = list.getFirst();
    Integer oldTop = list.get(oldSize - 1);

    // Act
    boolean removed = ListUtils.removeBySwapLast(list, oldFirst);

    // Assert
    assertTrue(removed);
    assertEquals(oldSize - 1, list.size());
    assertFalse(list.contains(oldFirst));
    assertEquals(oldTop, list.getFirst());
    for (int i = 1; i < list.size(); i++) {
      assertEquals(Integer.valueOf(i), list.get(i));
    }
  }

  @Test
  void removeBySwapLastIndex_whenRemovingLast_expectReturnsOldTopAndRemovesIt() {
    // Arrange
    ArrayList<Integer> list = new ArrayList<>();
    for (int i = 0; i < 10; i++) list.add(i);
    int oldSize = list.size();
    Integer oldTop = list.get(oldSize - 1);

    // Act
    Integer moved = ListUtils.removeBySwapLast(list, oldSize - 1);

    // Assert
    assertEquals(oldTop, moved);
    assertEquals(oldSize - 1, list.size());
    assertFalse(list.contains(oldTop));
    for (int i = 0; i < list.size(); i++) {
      assertEquals(Integer.valueOf(i), list.get(i));
    }
  }

  @Test
  void removeBySwapLastIndex_whenRemovingFirst_expectReturnsOldTopAndMovesItToZero() {
    // Arrange
    ArrayList<Integer> list = new ArrayList<>();
    for (int i = 0; i < 10; i++) list.add(i);
    int oldSize = list.size();
    Integer oldFirst = list.getFirst();
    Integer oldTop = list.get(oldSize - 1);

    // Act
    Integer moved = ListUtils.removeBySwapLast(list, 0);

    // Assert
    assertEquals(oldTop, moved);
    assertEquals(oldSize - 1, list.size());
    assertFalse(list.contains(oldFirst));
    assertEquals(oldTop, list.getFirst());
    for (int i = 1; i < list.size(); i++) {
      assertEquals(Integer.valueOf(i), list.get(i));
    }
  }

  @ParameterizedTest
  @CsvSource({"-1", "10"})
  @DisplayName("removeBySwapLast(index) throws on invalid indices")
  void removeBySwapLastIndex_whenInvalid_expectIndexOutOfBounds(int badIndex) {
    ArrayList<Integer> list = new ArrayList<>();
    for (int i = 0; i < 10; i++) list.add(i);
    assertThrows(IndexOutOfBoundsException.class, () -> ListUtils.removeBySwapLast(list, badIndex));
  }

  @Test
  void removeBySwapLastObject_whenListContainsNull_expectRemovesNullAndMovesLast() {
    ArrayList<String> list = new ArrayList<>(Arrays.asList(null, "X", "Y"));
    boolean removed = ListUtils.removeBySwapLast(list, null);
    assertTrue(removed);
    assertEquals(2, list.size());
    assertFalse(list.contains(null));
    assertEquals("Y", list.getFirst());
    assertEquals("X", list.getLast());
  }

  @Test
  void removeBySwapLastObject_whenNullNotPresent_expectNoChange() {
    ArrayList<String> list = new ArrayList<>(Arrays.asList("A", "B"));
    boolean removed = ListUtils.removeBySwapLast(list, null);
    assertFalse(removed);
    assertEquals(2, list.size());
    assertEquals("A", list.getFirst());
    assertEquals("B", list.getLast());
  }

  @Test
  void removeBySwapLastObject_whenDuplicates_expectRemovesOneAndKeepsAnother() {
    ArrayList<String> list = new ArrayList<>(Arrays.asList("A", "B", "C", "B"));
    boolean removed = ListUtils.removeBySwapLast(list, "B");
    assertTrue(removed);
    assertEquals(3, list.size());
    assertEquals(1, Collections.frequency(list, "B"));
    assertTrue(list.contains("C"));
    assertEquals("C", list.getLast());
  }

  static class NotRandomAlwaysTop extends Random {
    // Fake random, always remove the highest possible value in nextInt
    @Override
    public int nextInt(int top) {
      return top - 1;
    }
  }

  static class NotRandomAlwaysZero extends Random {
    // Fake random, always remove the lowest possible value in nextInt
    @Override
    public int nextInt(int top) {
      return 0;
    }
  }

  @Test
  void removeRandomBySwapLast_whenListEmpty_expectNull() {
    // Arrange
    ArrayList<Integer> list = new ArrayList<>();
    Random rand = new Random(123);

    // Act
    ListUtils.RandomRemoveResult<Integer> res = ListUtils.removeRandomBySwapLast(rand, list);

    // Assert
    assertNull(res);
    assertEquals(0, list.size());
  }

  @Test
  void removeRandomBySwapLast_whenRandomGeneral_expectRemovedNotInListAndMovedInvariant() {
    // Arrange
    ArrayList<Integer> list = new ArrayList<>();
    for (int i = 0; i < 10; i++) list.add(i);
    Random rand = new Random(42);

    // Act & Assert (per-iteration invariants)
    for (int i = 0; i < 10; i++) {
      assertEquals(10 - i, list.size());
      ListUtils.RandomRemoveResult<Integer> res = ListUtils.removeRandomBySwapLast(rand, list);
      assertNotNull(res);
      if (i < 9) {
        assertFalse(list.contains(res.removed()));
        assertTrue(res.removed().equals(res.moved()) || list.contains(res.moved()));
      } else {
        // last removal happens via size==1 short-circuit
        assertEquals(res.removed(), res.moved());
      }
    }
    assertEquals(0, list.size());
  }

  @Test
  void removeRandomBySwapLast_whenRandomAlwaysTop_expectRemovesLastAndMovedEqualsRemoved() {
    // Arrange
    ArrayList<Integer> list = new ArrayList<>();
    for (int i = 0; i < 10; i++) list.add(i);
    Random rand = new NotRandomAlwaysTop();
    assertEquals(999, rand.nextInt(1000));
    assertEquals(99, rand.nextInt(100));
    assertEquals(9, rand.nextInt(10));
    int oldSize = list.size();
    Integer oldTop = list.get(oldSize - 1);

    // Act
    ListUtils.RandomRemoveResult<Integer> res = ListUtils.removeRandomBySwapLast(rand, list);

    // Assert
    assertNotNull(res);
    assertEquals(oldTop, res.moved());
    assertEquals(res.moved(), res.removed());
    assertEquals(oldSize - 1, list.size());
    for (int i = 0; i < list.size(); i++) {
      assertEquals(Integer.valueOf(i), list.get(i));
    }
  }

  @Test
  void removeRandomBySwapLast_whenRandomAlwaysZero_expectRemovesFirstAndMovesLastToFirst() {
    // Arrange
    ArrayList<Integer> list = new ArrayList<>();
    for (int i = 0; i < 10; i++) list.add(i);
    Random rand = new NotRandomAlwaysZero();
    assertEquals(0, rand.nextInt(1000));
    assertEquals(0, rand.nextInt(100));
    assertEquals(0, rand.nextInt(10));
    int oldSize = list.size();
    Integer oldFirst = list.getFirst();
    Integer oldTop = list.get(oldSize - 1);

    // Act
    ListUtils.RandomRemoveResult<Integer> res = ListUtils.removeRandomBySwapLast(rand, list);

    // Assert
    assertNotNull(res);
    assertEquals(oldFirst, res.removed());
    assertEquals(oldTop, res.moved());
    assertEquals(oldTop, list.getFirst());
    assertEquals(oldSize - 1, list.size());
    for (int i = 1; i < list.size(); i++) {
      assertEquals(Integer.valueOf(i), list.get(i));
    }
  }

  @Test
  void removeRandomBySwapLastSimple_whenListEmpty_expectNull() {
    // Arrange
    ArrayList<Integer> list = new ArrayList<>();
    Random rand = new Random(99);

    // Act
    Integer res = ListUtils.removeRandomBySwapLastSimple(rand, list);

    // Assert
    assertNull(res);
    assertEquals(0, list.size());
  }

  @Test
  void removeRandomBySwapLastSimple_whenRandomGeneral_expectRemovedNotInList() {
    // Arrange
    ArrayList<Integer> list = new ArrayList<>();
    for (int i = 0; i < 10; i++) list.add(i);
    Random rand = new Random(17);

    // Act & Assert (per-iteration invariants)
    for (int i = 0; i < 10; i++) {
      assertEquals(10 - i, list.size());
      Integer removed = ListUtils.removeRandomBySwapLastSimple(rand, list);
      assertNotNull(removed);
      if (i < 9) {
        assertFalse(list.contains(removed));
      }
    }
    assertEquals(0, list.size());
  }

  @Test
  void removeRandomBySwapLastSimple_whenRandomAlwaysTop_expectRemovesLast() {
    // Arrange
    ArrayList<Integer> list = new ArrayList<>();
    for (int i = 0; i < 10; i++) list.add(i);
    Random rand = new NotRandomAlwaysTop();
    assertEquals(999, rand.nextInt(1000));
    assertEquals(99, rand.nextInt(100));
    assertEquals(9, rand.nextInt(10));
    int oldSize = list.size();
    Integer oldTop = list.get(oldSize - 1);

    // Act
    Integer removed = ListUtils.removeRandomBySwapLastSimple(rand, list);

    // Assert
    assertEquals(oldTop, removed);
    assertEquals(oldSize - 1, list.size());
    for (int i = 0; i < list.size(); i++) {
      assertEquals(Integer.valueOf(i), list.get(i));
    }
  }

  @Test
  void removeRandomBySwapLastSimple_whenRandomAlwaysZero_expectRemovesFirstAndMovesLastToFirst() {
    // Arrange
    ArrayList<Integer> list = new ArrayList<>();
    for (int i = 0; i < 10; i++) list.add(i);
    Random rand = new NotRandomAlwaysZero();
    assertEquals(0, rand.nextInt(1000));
    assertEquals(0, rand.nextInt(100));
    assertEquals(0, rand.nextInt(10));
    int oldSize = list.size();
    Integer oldFirst = list.getFirst();
    Integer oldTop = list.get(oldSize - 1);

    // Act
    Integer removed = ListUtils.removeRandomBySwapLastSimple(rand, list);

    // Assert
    assertEquals(oldFirst, removed);
    assertEquals(oldTop, list.getFirst());
    assertEquals(oldSize - 1, list.size());
    for (int i = 1; i < list.size(); i++) {
      assertEquals(Integer.valueOf(i), list.get(i));
    }
  }

  @Test
  void removeRandomBySwapLast_whenSizeOne_expectNoRandomCallAndMovedEqualsRemoved() {
    ArrayList<Integer> list = new ArrayList<>();
    list.add(42);
    Random random = mock(Random.class);

    ListUtils.RandomRemoveResult<Integer> result = ListUtils.removeRandomBySwapLast(random, list);

    assertNotNull(result);
    assertEquals(42, result.removed());
    assertEquals(42, result.moved());
    assertEquals(0, list.size());
    verifyNoInteractions(random);
  }

  @Test
  void removeRandomBySwapLastSimple_whenSizeOne_expectNoRandomCall() {
    ArrayList<Integer> list = new ArrayList<>();
    list.add(7);
    Random random = mock(Random.class);

    Integer removed = ListUtils.removeRandomBySwapLastSimple(random, list);

    assertEquals(7, removed);
    assertEquals(0, list.size());
    verifyNoInteractions(random);
  }
}

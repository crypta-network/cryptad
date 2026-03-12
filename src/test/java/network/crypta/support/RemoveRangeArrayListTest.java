package network.crypta.support;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100") // test method names use given_when_then convention with underscores
class RemoveRangeArrayListTest {

  @Test
  void removeRange_whenValidMiddleRange_removesExpectedElements() {
    // Arrange
    RemoveRangeArrayList<Integer> list = new RemoveRangeArrayList<>(10);
    list.addAll(Arrays.asList(0, 1, 2, 3, 4));

    // Act
    list.removeRange(1, 3); // remove indices [1,3) => removes 1 and 2

    // Assert
    assertEquals(List.of(0, 3, 4), list);
  }

  @Test
  void removeRange_whenFromEqualsToIndex_doesNothing() {
    // Arrange
    RemoveRangeArrayList<Integer> list = new RemoveRangeArrayList<>(5);
    list.addAll(Arrays.asList(0, 1, 2, 3, 4));

    // Act
    list.removeRange(2, 2);

    // Assert
    assertEquals(List.of(0, 1, 2, 3, 4), list);
  }

  @Test
  void removeRange_whenRemoveAll_clearsList() {
    // Arrange
    RemoveRangeArrayList<Integer> list = new RemoveRangeArrayList<>(5);
    list.addAll(Arrays.asList(0, 1, 2, 3, 4));

    // Act
    list.removeRange(0, list.size());

    // Assert
    assertEquals(List.of(), list);
  }

  @Test
  @SuppressWarnings("MismatchedQueryAndUpdateOfCollection")
  void removeRange_whenFromIndexNegative_throwsIndexOutOfBounds() {
    // Arrange
    RemoveRangeArrayList<Integer> list = new RemoveRangeArrayList<>(3);
    list.addAll(Arrays.asList(0, 1, 2));

    // Act + Assert
    assertThrows(IndexOutOfBoundsException.class, () -> list.removeRange(-1, 2));
  }

  @Test
  @SuppressWarnings("MismatchedQueryAndUpdateOfCollection")
  void removeRange_whenToIndexExceedsSize_throwsIndexOutOfBounds() {
    // Arrange
    RemoveRangeArrayList<Integer> list = new RemoveRangeArrayList<>(3);
    list.addAll(Arrays.asList(0, 1, 2));

    // Act + Assert
    assertThrows(IndexOutOfBoundsException.class, () -> list.removeRange(1, 4));
  }

  @Test
  @SuppressWarnings("MismatchedQueryAndUpdateOfCollection")
  void removeRange_whenFromIndexGreaterThanToIndex_throwsIndexOutOfBounds() {
    // Arrange
    RemoveRangeArrayList<Integer> list = new RemoveRangeArrayList<>(5);
    list.addAll(Arrays.asList(0, 1, 2, 3, 4));

    // Act + Assert
    assertThrows(IndexOutOfBoundsException.class, () -> list.removeRange(4, 3));
  }
}

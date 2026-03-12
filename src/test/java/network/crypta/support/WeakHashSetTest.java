package network.crypta.support;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // test method naming: method_whenCondition_expectOutcome
class WeakHashSetTest {

  @Test
  void add_whenNewElement_expectAddedAndContainsAndSizeIncrements() {
    // Arrange
    WeakHashSet<String> set = new WeakHashSet<>();

    // Act
    boolean added = set.add("a");

    // Assert
    assertTrue(added, "First add should report true");
    assertTrue(set.contains("a"), "Set should contain added element");
    assertEquals(1, set.size(), "Size should reflect single element");
    assertFalse(set.isEmpty(), "Set should not be empty after add");
  }

  @Test
  void add_whenDuplicate_expectFalseAndNoSizeChange() {
    // Arrange
    WeakHashSet<String> set = new WeakHashSet<>();
    assertTrue(set.add("x"));

    // Act
    boolean addedAgain = set.add("x");

    // Assert
    assertFalse(addedAgain, "Adding duplicate should return false");
    assertEquals(1, set.size(), "Duplicate add must not change size");
  }

  @Test
  void add_whenNull_expectAcceptedContainsAndRemovalWorks() {
    // Arrange
    WeakHashSet<String> set = new WeakHashSet<>();

    // Act
    boolean addedNull = set.add(null);

    // Assert
    assertTrue(addedNull, "WeakHashSet should accept null keys");
    assertTrue(set.contains(null), "Set should contain null after add");
    assertEquals(1, set.size());

    // Act / Assert removal
    assertTrue(set.remove(null), "Removing existing null should succeed");
    assertFalse(set.contains(null));
    assertEquals(0, set.size());
  }

  @Test
  void remove_whenMissing_expectFalse() {
    // Arrange
    WeakHashSet<String> set = new WeakHashSet<>();
    set.add("present");

    // Act / Assert
    assertFalse(set.remove("absent"), "Removing non-existent element should return false");
    assertEquals(1, set.size());
  }

  @Test
  @SuppressWarnings("SuspiciousMethodCalls")
  void containsAll_whenVariousCollections_expectCorrect() {
    // Arrange
    WeakHashSet<String> set = new WeakHashSet<>();
    set.add("a");
    set.add("b");
    set.add("c");

    // Act / Assert
    assertTrue(set.containsAll(Arrays.asList("a", "b")), "Should contain subset");
    assertFalse(set.containsAll(Arrays.asList("a", "d")), "Missing element should cause false");
    assertTrue(set.containsAll(List.of()), "ContainsAll on empty collection must be true");
  }

  @Test
  void iterator_whenRemoveDuringIteration_expectElementRemoved() {
    // Arrange
    WeakHashSet<String> set = new WeakHashSet<>();
    set.add("a");
    set.add("b");
    assertEquals(2, set.size());

    // Act: remove the first element encountered by the iterator
    Iterator<String> it = set.iterator();
    assertTrue(it.hasNext(), "Iterator should have at least one element");
    String first = it.next();
    it.remove();

    // Assert
    assertFalse(set.contains(first), "Removed element should no longer be in the set");
    assertEquals(1, set.size(), "Size should decrease after iterator.remove()");
    // The other element should still be present
    assertTrue(set.contains("a") || set.contains("b"), "One element must remain");
  }

  @Test
  void toArray_whenNoArg_expectAllElementsPresent() {
    // Arrange
    WeakHashSet<String> set = new WeakHashSet<>();
    set.add("alpha");
    set.add("beta");
    set.add("gamma");

    // Act
    Object[] arr = set.toArray();

    // Assert (order not guaranteed)
    assertEquals(3, arr.length);
    List<Object> list = Arrays.asList(arr);
    assertTrue(
        list.containsAll(List.of("alpha", "beta", "gamma")),
        "toArray() should contain all elements");
  }

  @Test
  void toArray_withTypedArrayLarger_expectReuseAndTrailingNull() {
    // Arrange
    WeakHashSet<String> set = new WeakHashSet<>();
    set.add("a");
    set.add("b");
    String[] target = new String[5];

    // Act
    String[] result = set.toArray(target);

    // Assert
    assertSame(target, result, "Should reuse provided array when large enough");
    // First two slots should be populated with the two elements in unspecified order
    Set<String> firstTwo = new HashSet<>();
    firstTwo.add(result[0]);
    firstTwo.add(result[1]);
    assertTrue(
        firstTwo.contains("a") && firstTwo.contains("b"),
        "First two positions should contain both elements");
    assertNull(result[2], "Element immediately following the last should be null");
  }

  @Test
  @SuppressWarnings("ConstantValue")
  void clear_whenNonEmpty_expectEmptyAfterClear() {
    // Arrange
    WeakHashSet<Integer> set = new WeakHashSet<>();
    set.add(1);
    set.add(2);
    assertEquals(2, set.size());

    // Act
    set.clear();

    // Assert
    assertTrue(set.isEmpty());
    assertEquals(0, set.size());
    assertArrayEquals(new Object[0], set.toArray());
  }

  @Test
  void equals_and_hashCode_whenSameElements_expectEqualAndConsistent() {
    // Arrange
    WeakHashSet<String> weakSet = new WeakHashSet<>();
    weakSet.add("x");
    weakSet.add("y");
    Set<String> hashSet = new HashSet<>();
    hashSet.add("y");
    hashSet.add("x");

    // Act / Assert
    assertEquals(weakSet, hashSet, "Sets with same elements should be equal");
    assertEquals(hashSet, weakSet, "Equality should be symmetric");
    assertEquals(hashSet.hashCode(), weakSet.hashCode(), "Equal sets must have equal hash codes");
  }
}

package network.crypta.support;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@SuppressWarnings("java:S100") // Test method naming: method_whenCondition_expectOutcome
class RandomArrayIteratorTest {
  private static final int NUM_ELEMENTS = 100;

  private RandomArrayIterator<Integer> iter;
  private Integer[] numbers;

  private static RandomArrayIterator<Integer> constructIterator(Integer[] data) {
    return new RandomArrayIterator<>(data);
  }

  @BeforeEach
  void setUp() {
    numbers = new Integer[NUM_ELEMENTS];
    for (int i = 0; i < NUM_ELEMENTS; i++) {
      numbers[i] = i;
    }
    iter = new RandomArrayIterator<>(numbers);
  }

  @Test
  @DisplayName("constructor_whenArrayNull_expectNullPointerException")
  void constructor_whenArrayNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, () -> assertNotNull(constructIterator(null)));
  }

  @Test
  @DisplayName("iteration_whenNoRandom_expectDefaultOrder")
  void iteration_whenNoRandom_expectDefaultOrder() {
    List<Integer> seen = new ArrayList<>(NUM_ELEMENTS);
    while (iter.hasNext()) {
      seen.add(iter.next());
    }
    //noinspection ConstantValue
    assertFalse(iter.hasNext());
    assertArrayEquals(numbers, seen.toArray(new Integer[0]));
  }

  @Test
  @DisplayName("reset_whenNull_expectRepeatPreviousOrder")
  void reset_whenNull_expectRepeatPreviousOrder() {
    // Arrange: randomize to get a non-default deterministic order
    iter.reset(new Random(1234L));
    List<Integer> first = new ArrayList<>(NUM_ELEMENTS);
    while (iter.hasNext()) {
      first.add(iter.next());
    }

    // Act: resetting with null must repeat exact same order
    iter.reset(null);
    List<Integer> second = new ArrayList<>(NUM_ELEMENTS);
    while (iter.hasNext()) {
      second.add(iter.next());
    }

    // Assert
    assertArrayEquals(first.toArray(new Integer[0]), second.toArray(new Integer[0]));
    assertFalse(java.util.Arrays.equals(numbers, second.toArray(new Integer[0])));
  }

  @Test
  @DisplayName("reset_whenNewRandom_expectNewDeterministicPermutation")
  void reset_whenNewRandom_expectNewDeterministicPermutation() {
    // Arrange: complete a randomized run with seed A
    iter.reset(new Random(42L));
    List<Integer> runA = new ArrayList<>(NUM_ELEMENTS);
    while (iter.hasNext()) {
      runA.add(iter.next());
    }

    // Act: reset with a different seed and collect a new run
    iter.reset(new Random(99L));
    List<Integer> runB = new ArrayList<>(NUM_ELEMENTS);
    while (iter.hasNext()) {
      runB.add(iter.next());
    }

    // Assert: same size, both permutations of inputs, and (very likely) different
    assertEquals(NUM_ELEMENTS, runA.size());
    assertEquals(NUM_ELEMENTS, runB.size());
    assertTrue(isPermutationOf(numbers, runA));
    assertTrue(isPermutationOf(numbers, runB));
    assertNotEquals(runA, runB);
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 1, 3, 10})
  @DisplayName("iteration_withRandom_expectPermutationNoDuplicates")
  void iteration_withRandom_expectPermutationNoDuplicates(int size) {
    Integer[] data = new Integer[size];
    for (int i = 0; i < size; i++) {
      data[i] = i;
    }
    RandomArrayIterator<Integer> it = new RandomArrayIterator<>(data, new Random(7L));

    List<Integer> seen = new ArrayList<>(size);
    while (it.hasNext()) {
      seen.add(it.next());
    }

    assertEquals(size, seen.size());
    assertTrue(isPermutationOf(data, seen));
  }

  @Test
  @DisplayName("next_whenExhausted_expectNoSuchElementException")
  void next_whenExhausted_expectNoSuchElementException() {
    // Exhaust iterator first
    while (iter.hasNext()) {
      iter.next();
    }
    //noinspection ConstantValue
    assertFalse(iter.hasNext());
    assertThrows(NoSuchElementException.class, () -> iter.next());
  }

  @Test
  @DisplayName("remove_always_expectUnsupportedOperationException")
  void remove_always_expectUnsupportedOperationException() {
    // Call remove both before and after next() to make intent explicit
    assertThrows(UnsupportedOperationException.class, () -> iter.remove());

    if (iter.hasNext()) {
      iter.next();
      assertThrows(UnsupportedOperationException.class, () -> iter.remove());
    }

    // Ensure iteration order remains intact (defaults)
    iter.reset(null);
    for (int i = 0; i < NUM_ELEMENTS; i++) {
      assertTrue(iter.hasNext());
      assertEquals(i, iter.next());
    }
    assertFalse(iter.hasNext());
  }

  @Test
  @DisplayName("emptyArray_whenIterating_expectNoNextAndExceptions")
  void emptyArray_whenIterating_expectNoNextAndExceptions() {
    RandomArrayIterator<Integer> empty = new RandomArrayIterator<>(new Integer[0]);
    assertFalse(empty.hasNext());
    assertThrows(NoSuchElementException.class, empty::next);
    assertThrows(UnsupportedOperationException.class, empty::remove);
  }

  private static boolean isPermutationOf(Integer[] reference, List<Integer> seen) {
    if (reference.length != seen.size()) {
      return false;
    }
    Set<Integer> ref = new HashSet<>();
    java.util.Collections.addAll(ref, reference);
    return ref.equals(new HashSet<>(seen));
  }
}

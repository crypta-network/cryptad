package com.jthemedetecor.util;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class ConcurrentHashSetTest {

  @Test
  void constructor_whenNew_expectEmptySet() {
    assertEmptySetState(new ConcurrentHashSet<>());
  }

  @Test
  void add_whenElementAbsent_expectElementAdded() {
    ConcurrentHashSet<String> set = new ConcurrentHashSet<>();

    boolean added = set.add("dark");

    assertAll(
        () -> assertTrue(added),
        () -> assertTrue(set.contains("dark")),
        () -> assertEquals(1, set.size()));
  }

  @Test
  void add_whenElementAlreadyPresent_expectFalseAndNoDuplicate() {
    ConcurrentHashSet<String> set = new ConcurrentHashSet<>();
    set.add("dark");

    boolean added = set.add("dark");

    assertAll(() -> assertFalse(added), () -> assertEquals(1, set.size()));
  }

  @Test
  void add_whenElementIsNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, ConcurrentHashSetTest::addNullToEmptySet);
  }

  @Test
  void contains_whenElementIsNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, ConcurrentHashSetTest::containsNullInEmptySet);
  }

  @Test
  void remove_whenElementIsNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, ConcurrentHashSetTest::removeNullFromEmptySet);
  }

  @Test
  void remove_whenElementPresent_expectRemoved() {
    ConcurrentHashSet<String> set = new ConcurrentHashSet<>();
    set.add("dark");

    boolean removed = set.remove("dark");

    assertAll(
        () -> assertTrue(removed),
        () -> assertFalse(set.contains("dark")),
        () -> assertTrue(set.isEmpty()));
  }

  @Test
  void remove_whenElementAbsent_expectFalse() {
    assertFalse(new ConcurrentHashSet<String>().remove("missing"));
  }

  @Test
  void containsAll_whenCollectionHasMissingElement_expectFalse() {
    ConcurrentHashSet<String> set = new ConcurrentHashSet<>();
    set.addAll(List.of("dark", "light"));

    boolean containsAll = set.containsAll(List.of("dark", "missing"));

    assertFalse(containsAll);
  }

  @Test
  void addAll_whenCollectionHasNewAndExistingElements_expectChangedUniqueContents() {
    ConcurrentHashSet<String> set = new ConcurrentHashSet<>();
    set.add("dark");

    boolean changed = set.addAll(List.of("dark", "light", "contrast"));

    assertAll(
        () -> assertTrue(changed),
        () -> assertEquals(3, set.size()),
        () -> assertTrue(set.containsAll(List.of("dark", "light", "contrast"))));
  }

  @Test
  void addAll_whenCollectionContainsOnlyExistingElements_expectFalse() {
    ConcurrentHashSet<String> set = new ConcurrentHashSet<>();
    set.addAll(List.of("dark", "light"));

    boolean changed = set.addAll(List.of("dark", "light"));

    assertFalse(changed);
  }

  @Test
  void iterator_whenElementsAdded_expectTraversesAllMembers() {
    ConcurrentHashSet<String> set = new ConcurrentHashSet<>();
    set.addAll(List.of("dark", "light", "contrast"));

    Iterator<String> iterator = set.iterator();
    Set<String> iteratedValues = new HashSet<>();
    while (iterator.hasNext()) {
      iteratedValues.add(iterator.next());
    }

    assertEquals(Set.of("dark", "light", "contrast"), iteratedValues);
  }

  @Test
  void toArray_whenDestinationArrayLargerThanSet_expectNullSentinelInReturnedArray() {
    ConcurrentHashSet<String> set = new ConcurrentHashSet<>();
    set.addAll(List.of("dark", "light"));
    String[] destination = {"keep", "keep", "keep"};

    String[] array = set.toArray(destination);

    Set<String> actualValues = new HashSet<>();
    actualValues.add(array[0]);
    actualValues.add(array[1]);

    assertAll(
        () -> assertSame(destination, array),
        () -> assertEquals(Set.of("dark", "light"), actualValues),
        () -> assertNull(array[2]));
  }

  @Test
  void toArray_whenDestinationArrayTooSmall_expectNewTypedArrayReturned() {
    ConcurrentHashSet<String> set = new ConcurrentHashSet<>();
    set.addAll(List.of("dark", "light"));
    String[] destination = new String[0];

    String[] array = set.toArray(destination);

    assertAll(
        () -> assertNotSame(destination, array),
        () -> assertEquals(Set.of("dark", "light"), Set.of(array)));
  }

  @Test
  void clear_whenElementsPresent_expectEmptySet() {
    ConcurrentHashSet<String> set = new ConcurrentHashSet<>();
    set.addAll(List.of("dark", "light"));

    set.clear();

    assertEmptySetState(set);
  }

  @Test
  void retainAll_whenCalled_expectUnsupportedOperationException() {
    ConcurrentHashSet<String> set = new ConcurrentHashSet<>();
    List<String> retainedElements = List.of("dark");

    assertThrows(UnsupportedOperationException.class, () -> set.retainAll(retainedElements));
  }

  @Test
  void removeAll_whenCalled_expectUnsupportedOperationException() {
    ConcurrentHashSet<String> set = new ConcurrentHashSet<>();
    List<String> removedElements = List.of("dark");

    assertThrows(UnsupportedOperationException.class, () -> set.removeAll(removedElements));
  }

  @Test
  void add_whenCalledConcurrently_expectUniqueValuesRetained() throws Exception {
    ConcurrentHashSet<Integer> set = new ConcurrentHashSet<>();
    int threadCount = 4;
    int uniqueValueCount = 100;
    CountDownLatch start = new CountDownLatch(1);
    List<Future<?>> futures = new ArrayList<>();

    try (ExecutorService executor = Executors.newFixedThreadPool(threadCount)) {
      for (int thread = 0; thread < threadCount; thread++) {
        futures.add(
            executor.submit(
                () -> {
                  start.await();
                  for (int value = 0; value < uniqueValueCount; value++) {
                    set.add(value);
                  }
                  return null;
                }));
      }

      start.countDown();
      for (Future<?> future : futures) {
        future.get(2, TimeUnit.SECONDS);
      }
    }

    assertAll(
        () -> assertEquals(uniqueValueCount, set.size()),
        () -> assertTrue(set.containsAll(expectedValues(uniqueValueCount))));
  }

  private static Set<Integer> expectedValues(int uniqueValueCount) {
    return IntStream.range(0, uniqueValueCount).boxed().collect(Collectors.toSet());
  }

  private static void assertEmptySetState(ConcurrentHashSet<?> set) {
    assertAll(
        () -> assertTrue(set.isEmpty()),
        () -> assertEquals(0, set.size()),
        () -> assertFalse(set.iterator().hasNext()),
        () -> assertArrayEquals(new Object[0], set.toArray()));
  }

  private static void addNullToEmptySet() {
    assertTrue(new ConcurrentHashSet<String>().add(null));
  }

  private static void containsNullInEmptySet() {
    assertTrue(new ConcurrentHashSet<String>().contains(null));
  }

  private static void removeNullFromEmptySet() {
    assertTrue(new ConcurrentHashSet<String>().remove(null));
  }
}

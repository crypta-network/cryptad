package com.onionnetworks.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class JoiningIteratorTest {

  @Test
  void hasNext_whenBothIteratorsEmpty_returnsFalse() {
    Iterator<Integer> first = Collections.emptyIterator();
    Iterator<Integer> second = Collections.emptyIterator();

    JoiningIterator<Integer> iterator = new JoiningIterator<>(first, second);

    assertFalse(iterator.hasNext());
  }

  @Test
  void next_whenBothIteratorsEmpty_throwsNoSuchElementException() {
    Iterator<Integer> first = Collections.emptyIterator();
    Iterator<Integer> second = Collections.emptyIterator();
    JoiningIterator<Integer> iterator = new JoiningIterator<>(first, second);

    assertThrows(java.util.NoSuchElementException.class, iterator::next);
  }

  @Test
  void next_whenFirstIteratorExhausted_continuesWithSecond() {
    Iterator<Integer> first = Collections.emptyIterator();
    Iterator<Integer> second = Arrays.asList(10, 20).iterator();
    JoiningIterator<Integer> iterator = new JoiningIterator<>(first, second);

    List<Integer> values = new ArrayList<>();
    while (iterator.hasNext()) {
      values.add(iterator.next());
    }

    assertEquals(Arrays.asList(10, 20), values);
  }

  @Test
  void next_whenFirstHasElements_returnsAllFromFirstThenSecond() {
    Iterator<String> first = Arrays.asList("a", "b").iterator();
    Iterator<String> second = Collections.singletonList("c").iterator();
    JoiningIterator<String> iterator = new JoiningIterator<>(first, second);

    List<String> values = new ArrayList<>();
    while (iterator.hasNext()) {
      values.add(iterator.next());
    }

    assertEquals(Arrays.asList("a", "b", "c"), values);
  }

  @Test
  void remove_alwaysThrowsUnsupportedOperationException() {
    Iterator<Integer> first = List.of(1).iterator();
    Iterator<Integer> second = List.of(2).iterator();
    JoiningIterator<Integer> iterator = new JoiningIterator<>(first, second);

    assertThrows(UnsupportedOperationException.class, iterator::remove);
  }
}

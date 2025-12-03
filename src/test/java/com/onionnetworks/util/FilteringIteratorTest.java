package com.onionnetworks.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class FilteringIteratorTest {

  @Test
  void hasNext_whenAcceptedElementAvailable_returnsTrueAndNextReturnsBuffered() {
    List<String> values = Arrays.asList("a", "b");
    FilteringIterator<String> iterator =
        new FilteringIterator<>(values.iterator()) {
          @Override
          protected boolean accept(String o) {
            return true;
          }
        };

    assertTrue(iterator.hasNext());
    assertEquals("a", iterator.next());
    assertTrue(iterator.hasNext());
    assertEquals("b", iterator.next());
    assertFalse(iterator.hasNext());
  }

  @Test
  void next_whenNoElementPasses_throwsNoSuchElementException() {
    List<String> values = List.of("ignored");
    FilteringIterator<String> iterator =
        new FilteringIterator<>(values.iterator()) {
          @Override
          protected boolean accept(String o) {
            return false;
          }
        };

    assertFalse(iterator.hasNext());
    assertThrows(NoSuchElementException.class, iterator::next);
  }

  @Test
  void remove_whenCalled_throwsUnsupportedOperationException() {
    FilteringIterator<String> iterator =
        new FilteringIterator<>(Collections.emptyIterator()) {
          @Override
          protected boolean accept(String o) {
            return true;
          }
        };

    assertThrows(UnsupportedOperationException.class, iterator::remove);
  }

  @Test
  void hasNext_calledMultipleTimesBeforeNext_doesNotAdvanceParentBeyondBuffered() {
    CountingIterator parent = new CountingIterator(Arrays.asList("keep", "skip").iterator());
    FilteringIterator<String> iterator =
        new FilteringIterator<>(parent) {
          @Override
          protected boolean accept(String o) {
            return "keep".equals(o);
          }
        };

    assertTrue(iterator.hasNext());
    //noinspection ConstantValue
    assertTrue(iterator.hasNext());
    assertEquals(1, parent.nextCalls);

    assertEquals("keep", iterator.next());
    assertFalse(iterator.hasNext());
    assertEquals(2, parent.nextCalls);
  }

  @Test
  void iteration_whenSkippingNulls_onlyReturnsAcceptedAndTracksAcceptCalls() {
    List<String> seen = new ArrayList<>();
    FilteringIterator<String> iterator =
        new FilteringIterator<>(Arrays.asList(null, "ok", null).iterator()) {
          @Override
          protected boolean accept(String o) {
            seen.add(o);
            return o != null;
          }
        };

    List<String> returned = new ArrayList<>();
    while (iterator.hasNext()) {
      returned.add(iterator.next());
    }

    assertEquals(Arrays.asList(null, "ok", null), seen);
    assertEquals(List.of("ok"), returned);
  }

  private static final class CountingIterator implements Iterator<String> {
    private final Iterator<String> delegate;
    int nextCalls;

    CountingIterator(Iterator<String> delegate) {
      this.delegate = delegate;
    }

    @Override
    public boolean hasNext() {
      return delegate.hasNext();
    }

    @Override
    public String next() {
      nextCalls++;
      return delegate.next();
    }
  }
}

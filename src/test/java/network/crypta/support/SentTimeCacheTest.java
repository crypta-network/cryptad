package network.crypta.support;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link SentTimeCache}.
 *
 * <p>These tests follow AAA style and cover: capacity enforcement, FIFO eviction, updating existing
 * entries without affecting eviction order, missing queries, negative times, and timing behavior of
 * {@link SentTimeCache#sent(int)}.
 */
@SuppressWarnings("java:S100") // Allow method names with underscores for clarity.
class SentTimeCacheTest {
  private static final int CACHE_SIZE = 32;

  @Test
  void size_whenNew_returnsZero() {
    // Arrange
    SentTimeCache c = new SentTimeCache(CACHE_SIZE);
    // Act
    int actual = c.size();
    // Assert
    assertEquals(0, actual);
  }

  @Test
  void report_whenOverCapacity_evictsOldest() {
    // Arrange
    SentTimeCache c = newCache();
    fillWithSequence(c);
    // Act: exceed capacity by one using sent()
    c.sent(CACHE_SIZE + 1);
    // Assert: capacity stays bounded
    assertEquals(CACHE_SIZE, c.size());
  }

  @Test
  void queryAndRemove_whenPresent_returnsStoredTimeAndRemoves() {
    // Arrange
    SentTimeCache c = newCache();
    fillWithSequence(c);

    // Act & Assert: each removal returns its time and shrinks size
    for (int n = 1; n <= CACHE_SIZE; n++) {
      long t = c.queryAndRemove(n);
      assertEquals(n, t);
      assertEquals(CACHE_SIZE - n, c.size());
    }
  }

  @Test
  void queryAndRemove_whenMissing_returnsNegative() {
    // Arrange
    SentTimeCache c = newCache();
    // Act
    long t = c.queryAndRemove(42);
    // Assert
    assertTrue(t < 0, "Expected negative value for missing entry");
  }

  @Test
  void report_whenCapacityExceeded_behavesAsFifo() {
    // Arrange
    SentTimeCache c = newCache();
    fillWithSequence(c);

    // Act & Assert: push out the oldest each time
    for (int n = 1; n <= CACHE_SIZE; n++) {
      c.report(n + CACHE_SIZE, n + CACHE_SIZE); // add one beyond capacity
      long removedCandidate = c.queryAndRemove(n); // should have been evicted
      assertTrue(removedCandidate < 0, "Oldest entry should have been evicted");
      assertEquals(CACHE_SIZE, c.size());
    }

    // Remaining are the newly inserted ones
    for (int n = 1; n <= CACHE_SIZE; n++) {
      long t = c.queryAndRemove(n + CACHE_SIZE);
      assertEquals(n + CACHE_SIZE, t);
    }
  }

  @Test
  void report_whenUpdatingExisting_updatesTimeButNotEvictionOrder() {
    // Arrange
    SentTimeCache c = new SentTimeCache(2);
    c.report(1, 100L);
    c.report(2, 200L);

    // Act: update existing key 1 (insertion order must remain 1,2)
    c.report(1, 300L);
    // Insert a third to force eviction of the eldest by insertion order (key 1)
    c.report(3, 400L);

    // Assert: key 1 was evicted despite being updated; key 2 and 3 remain
    assertTrue(c.queryAndRemove(1) < 0, "Key 1 should be evicted (FIFO by insertion order)");
    assertEquals(200L, c.queryAndRemove(2));
    assertEquals(400L, c.queryAndRemove(3));
  }

  @Test
  void report_whenNegativeTime_preservesNegativeValue() {
    // Arrange
    SentTimeCache c = newCache();
    // Act
    c.report(7, -123L);
    long t = c.queryAndRemove(7);
    // Assert
    assertEquals(-123L, t);
  }

  @Test
  void sent_whenCalled_recordsCurrentTimeWithinBounds() {
    // Arrange
    SentTimeCache c = newCache();
    long before = System.currentTimeMillis();

    // Act
    c.sent(99);
    long recorded = c.queryAndRemove(99);
    long after = System.currentTimeMillis();

    // Assert: recorded time is within [before, after]
    assertTrue(
        recorded >= before && recorded <= after,
        "Recorded time should be between invocation bounds");
  }

  @ParameterizedTest
  @ValueSource(ints = {0, -1, -10})
  void constructor_whenInvalidMaxSize_throws(int invalidMax) {
    // Arrange + Act + Assert
    assertThrows(IllegalArgumentException.class, () -> new SentTimeCache(invalidMax));
  }

  // Helpers
  private SentTimeCache newCache() {
    SentTimeCache c = new SentTimeCache(CACHE_SIZE);
    assertEquals(0, c.size());
    return c;
  }

  private void fillWithSequence(SentTimeCache c) {
    for (int n = 1; n <= CACHE_SIZE; n++) {
      c.report(n, n);
    }
    assertEquals(CACHE_SIZE, c.size());
  }
}

package network.crypta.support;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for {@link LRUCache}. Focus on public behavior: LRU eviction, promotion on get(),
 * expiration handling, null key exceptions, and clear(). Uses simple String keys (Comparable) and
 * Integer values.
 */
@SuppressWarnings("java:S100") // Allow method names with underscores
class LRUCacheTest {

  @Test
  @DisplayName("put/get without expiration returns value and get() promotes key")
  void get_whenNotExpired_promotesAndReturnsValue() {
    // Arrange
    LRUCache<String, Integer> cache = new LRUCache<>(2); // No expiration (Long.MAX_VALUE)
    cache.put("a", 1);
    cache.put("b", 2);

    // Act: promote "a" to most-recently-used
    Integer a1 = cache.get("a");
    cache.put("c", 3); // should evict least recently used: "b"

    // Assert
    assertEquals(1, a1);
    assertNull(cache.get("b"), "Expect LRU entry 'b' to be evicted after promoting 'a'.");
    assertEquals(1, cache.get("a"));
    assertEquals(3, cache.get("c"));
  }

  @Test
  @DisplayName("put beyond size evicts least-recently-used")
  void put_whenExceedsSize_evictsLeastRecentlyUsed() {
    // Arrange
    LRUCache<String, Integer> cache = new LRUCache<>(2);

    // Act
    cache.put("a", 1);
    cache.put("b", 2);
    cache.put("c", 3); // should evict "a"

    // Assert
    assertNull(cache.get("a"));
    assertEquals(2, cache.get("b"));
    assertEquals(3, cache.get("c"));
  }

  @Test
  @DisplayName("re-putting same key updates value and moves to MRU")
  void put_whenKeyExists_updatesValueAndPromotes() {
    // Arrange
    LRUCache<String, Integer> cache = new LRUCache<>(2);
    cache.put("a", 1);
    cache.put("b", 2);

    // Act: update existing key and thus promote it
    cache.put("a", 10);
    cache.put("c", 3); // should evict "b" (now the LRU)

    // Assert
    assertNull(cache.get("b"));
    assertEquals(10, cache.get("a"));
    assertEquals(3, cache.get("c"));
  }

  @Test
  @DisplayName("get on expired entry returns null and does not throw")
  void get_whenExpired_returnsNullAndDropsEntry() {
    // Arrange: negative delay guarantees immediate expiration
    LRUCache<String, Integer> cache = new LRUCache<>(2, -1L);
    cache.put("x", 42);

    // Act & Assert
    assertNull(cache.get("x"), "Expired entries must be treated as missing and removed.");

    // Also confirm cache remains usable after removing an expired entry
    cache.put("y", 7);
    // Immediate expiration still applies for this cache; get() returns null as well
    assertNull(cache.get("y"));
  }

  @Test
  @DisplayName("clear removes all entries")
  void clear_whenCalled_cacheIsEmpty() {
    // Arrange
    LRUCache<String, Integer> cache = new LRUCache<>(2);
    cache.put("a", 1);
    cache.put("b", 2);

    // Act
    cache.clear();

    // Assert
    assertNull(cache.get("a"));
    assertNull(cache.get("b"));
  }

  @Test
  @DisplayName("null key on put/get throws NullPointerException (delegated from LRUMap)")
  void methods_whenNullKey_throwNullPointerException() {
    // Arrange
    LRUCache<String, Integer> cache = new LRUCache<>(1);

    // Act & Assert
    assertThrows(NullPointerException.class, () -> cache.put(null, 1));
    assertThrows(NullPointerException.class, () -> cache.get(null));
  }

  @Test
  @DisplayName("size limit zero keeps cache always empty")
  void put_whenSizeLimitZero_neverStoresEntries() {
    // Arrange
    LRUCache<String, Integer> cache = new LRUCache<>(0);

    // Act
    cache.put("a", 1);
    cache.put("b", 2);

    // Assert: nothing can be stored
    assertNull(cache.get("a"));
    assertNull(cache.get("b"));
  }
}

package network.crypta.support;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Comparator;
import java.util.Iterator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link LRUMap}. Covers push/get/remove, LRU ordering, peeking/popping,
 * enumerations, array export, clearing, and safe-map factory methods.
 */
@SuppressWarnings("java:S100") // Allow method names with underscores for readability
class LRUMapTest {

  private static final int SAMPLE_ELEMS = 5;

  private Object[][] createSampleKeyVal(int size) {
    Object[][] arr = new Object[size][2];
    for (int i = 0; i < size; i++) {
      arr[i][0] = i; // key
      arr[i][1] = "V" + i; // value for easier assertions
    }
    return arr;
  }

  private LRUMap<Object, Object> createSampleMap(int size) {
    LRUMap<Object, Object> map = new LRUMap<>();
    Object[][] kv = createSampleKeyVal(size);
    for (Object[] objects : kv) map.push(objects[0], objects[1]);
    return map;
  }

  @Test
  @DisplayName("push with null key throws NPE; null value allowed")
  void push_whenNullKey_throwsAndNullValueAllowed() {
    // Arrange
    LRUMap<String, String> map = new LRUMap<>();

    // Act & Assert: null value is allowed
    map.push("k", null);
    assertTrue(map.containsKey("k"));
    assertNull(map.get("k"));

    // Act & Assert: null key not allowed
    assertThrows(NullPointerException.class, () -> map.push(null, "x"));
    assertThrows(NullPointerException.class, () -> map.push(null, null));
  }

  @Test
  @DisplayName("push same key returns old value and promotes to MRU")
  void push_whenKeyExists_returnsOldValueAndPromotes() {
    // Arrange
    LRUMap<String, String> map = new LRUMap<>();
    map.push("a", "A"); // LRU: a
    map.push("b", "B"); // LRU: a, b
    map.push("c", "C"); // LRU: a, b, c

    // Act
    String old = map.push("b", "B2"); // new order LRU: a, c, b (b is MRU)

    // Assert
    assertEquals("B", old, "push must return the previous value for the key");
    assertEquals("a", map.popKey());
    assertEquals("c", map.popKey());
    assertEquals("b", map.popKey());
    assertNull(map.popKey());
  }

  @Test
  @DisplayName("get returns value without promotion")
  void get_whenCalled_doesNotPromoteKey() {
    // Arrange
    LRUMap<String, String> map = new LRUMap<>();
    map.push("x", "X"); // LRU: x
    map.push("y", "Y"); // LRU: x, y

    // Act
    assertEquals("X", map.get("x")); // does not promote

    // Assert: x is still the least-recently-pushed
    assertEquals("x", map.peekKey());
    assertEquals("x", map.popKey());
    assertEquals("y", map.popKey());
  }

  @Test
  @DisplayName("popKey/popValue on empty return null")
  void pop_whenEmpty_returnsNull() {
    // Arrange
    LRUMap<Integer, Integer> map = new LRUMap<>();

    // Act & Assert
    assertNull(map.popKey());
    assertNull(map.popValue());
  }

  @Test
  @DisplayName("popKey removes and returns least-recently-pushed key")
  void popKey_whenCalled_returnsLRUKeyAndRemoves() {
    // Arrange
    LRUMap<Object, Object> map = createSampleMap(SAMPLE_ELEMS);

    // Act & Assert (order: 0 .. SAMPLE_ELEMS-1)
    for (int i = 0; i < SAMPLE_ELEMS; i++) {
      assertEquals(i, map.popKey());
    }
    assertNull(map.popKey());
  }

  @Test
  @DisplayName("popValue removes and returns least-recently-pushed value")
  void popValue_whenCalled_returnsLRUValueAndRemoves() {
    // Arrange
    LRUMap<Object, Object> map = createSampleMap(SAMPLE_ELEMS);

    // Act & Assert (values V0..Vn in LRU->MRU order)
    for (int i = 0; i < SAMPLE_ELEMS; i++) {
      assertEquals("V" + i, map.popValue());
    }
    assertNull(map.popValue());
  }

  @Test
  @DisplayName("peekKey/peekValue return LRU without removing")
  void peek_whenCalled_returnsLRUWithoutRemoving() {
    // Arrange
    LRUMap<Integer, String> map = new LRUMap<>();
    map.push(1, "one");
    map.push(2, "two");

    // Act & Assert
    assertEquals(1, map.peekKey());
    assertEquals("one", map.peekValue());
    assertEquals(2, map.size());
    assertEquals(1, map.popKey()); // still the LRU
  }

  @Test
  @DisplayName("containsKey/get/remove throw NPE on null key")
  void methods_whenNullKey_throwNullPointerException() {
    // Arrange
    LRUMap<String, Integer> map = new LRUMap<>();

    // Act & Assert
    assertThrows(NullPointerException.class, () -> map.containsKey(null));
    assertThrows(NullPointerException.class, () -> map.get(null));
    assertThrows(NullPointerException.class, () -> map.removeKey(null));
  }

  @Test
  @DisplayName("get on missing key returns null")
  void get_whenMissingKey_returnsNull() {
    // Arrange
    LRUMap<String, Integer> map = new LRUMap<>();
    map.push("a", 1);

    // Act & Assert
    assertNull(map.get("b"));
  }

  @Test
  @DisplayName("keys() iterates from LRU to MRU")
  void keys_whenIterated_returnsFromLRUToMRU() {
    // Arrange
    LRUMap<Object, Object> map = createSampleMap(SAMPLE_ELEMS);

    // Act
    Iterator<Object> keys = map.keys();

    // Assert
    int expected = 0;
    while (keys.hasNext()) {
      assertEquals(expected++, keys.next());
    }
    assertEquals(SAMPLE_ELEMS, expected);
  }

  @Test
  @DisplayName("values() iterates from LRU to MRU")
  void values_whenIterated_returnsFromLRUToMRU() {
    // Arrange
    LRUMap<Object, Object> map = createSampleMap(3); // values: V0, V1, V2

    // Act
    Iterator<Object> vals = map.values();

    // Assert
    assertTrue(vals.hasNext());
    assertEquals("V0", vals.next());
    assertEquals("V1", vals.next());
    assertEquals("V2", vals.next());
    assertFalse(vals.hasNext());
  }

  @Test
  @DisplayName("valuesToArray fills prefix in LRU->MRU order and leaves remaining null")
  void valuesToArray_whenArrayLarger_fillsPrefixAndLeavesNulls() {
    // Arrange
    LRUMap<Integer, String> map = new LRUMap<>();
    map.push(1, "A");
    map.push(2, "B");
    map.push(3, "C");
    String[] out = new String[5];

    // Act
    map.valuesToArray(out);

    // Assert
    assertArrayEquals(new String[] {"A", "B", "C", null, null}, out);
  }

  @Test
  @DisplayName("clear empties map and resets size")
  void clear_whenCalled_mapBecomesEmpty() {
    // Arrange
    LRUMap<Integer, Integer> map = new LRUMap<>();
    map.push(1, 10);
    map.push(2, 20);

    // Act
    map.clear();

    // Assert
    assertTrue(map.isEmpty());
    assertEquals(0, map.size());
    assertNull(map.popKey());
  }

  @Test
  @DisplayName("createSafeMap() with Comparable keys behaves correctly")
  void createSafeMap_whenComparableKey_works() {
    // Arrange
    LRUMap<Integer, String> map = LRUMap.createSafeMap();
    map.push(1, "A");
    map.push(2, "B");

    // Act & Assert
    assertEquals(1, map.popKey());
    assertEquals(2, map.popKey());
    assertNull(map.popKey());
  }

  private record NCKey(int id) { // Non-Comparable key for comparator-based safe map
  }

  @Test
  @DisplayName("createSafeMap(Comparator) accepts non-comparable keys")
  void createSafeMap_withComparator_acceptsNonComparableKey() {
    // Arrange
    LRUMap<NCKey, String> map = LRUMap.createSafeMap(Comparator.comparingInt(k -> k.id));
    NCKey k1 = new NCKey(1);
    NCKey k2 = new NCKey(2);
    map.push(k1, "one");
    map.push(k2, "two");

    // Act & Assert
    assertEquals("one", map.get(k1));
    assertEquals("two", map.get(k2));
    assertEquals(k1, map.popKey());
    assertEquals(k2, map.popKey());
  }

  @Test
  @DisplayName("size reflects pushes and pops; isEmpty tracks emptiness")
  void size_and_isEmpty_reflectState() {
    // Arrange
    LRUMap<Integer, String> map = new LRUMap<>();
    assertTrue(map.isEmpty());

    // Act & Assert
    map.push(1, "A");
    assertEquals(1, map.size());
    map.push(2, "B");
    assertEquals(2, map.size());
    assertFalse(map.isEmpty());
    map.popKey();
    assertEquals(1, map.size());
    map.popKey();
    assertEquals(0, map.size());
    assertTrue(map.isEmpty());
  }
}

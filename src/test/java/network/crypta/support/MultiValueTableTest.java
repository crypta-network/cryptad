package network.crypta.support;

import java.util.*;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MultiValueTableTest {

  @Test
  void keySet_isSnapshotAndUnmodifiable() {
    MultiValueTable<String, Integer> table = new MultiValueTable<>();
    table.put("a", 1);

    Set<String> keysSnapshot = table.keySet();
    assertTrue(keysSnapshot.contains("a"));

    table.put("b", 2);

    assertFalse(keysSnapshot.contains("b"), "Snapshot must not reflect later inserts");
    assertThrows(UnsupportedOperationException.class, () -> keysSnapshot.add("c"));
    assertThrows(UnsupportedOperationException.class, () -> keysSnapshot.remove("a"));
  }

  @Test
  void entrySet_isSnapshotAndEntriesUnmodifiable() {
    MultiValueTable<String, Integer> table = new MultiValueTable<>();
    table.put("x", 1);

    Set<Map.Entry<String, List<Integer>>> entriesSnapshot = table.entrySet();
    assertEquals(1, entriesSnapshot.size());

    table.put("y", 2);
    assertEquals(1, entriesSnapshot.size(), "Snapshot must not reflect later inserts");
    Map.Entry<String, List<Integer>> newEntry = Map.entry("z", List.of(3));
    assertThrows(UnsupportedOperationException.class, () -> entriesSnapshot.add(newEntry));

    Map.Entry<String, List<Integer>> any = entriesSnapshot.iterator().next();
    assertEquals("x", any.getKey());
    assertEquals(List.of(1), any.getValue());
    List<Integer> replacement = List.of(9);
    assertThrows(UnsupportedOperationException.class, () -> any.setValue(replacement));
  }

  @Test
  void values_isSnapshotAndUnmodifiable() {
    MultiValueTable<String, Integer> table = new MultiValueTable<>();
    table.put("k", 1);

    Collection<Integer> valuesSnapshot = table.values();
    assertEquals(List.of(1), new ArrayList<>(valuesSnapshot));

    table.put("k", 2);
    assertEquals(
        List.of(1), new ArrayList<>(valuesSnapshot), "Snapshot must not reflect later additions");
    assertThrows(UnsupportedOperationException.class, () -> valuesSnapshot.add(3));
  }
}

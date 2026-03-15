package network.crypta.runtime.spi;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class NodeFieldSetTest {

  @Test
  void empty_whenCalled_expectEmptyFieldSet() {
    NodeFieldSet fieldSet = NodeFieldSet.empty();

    assertTrue(fieldSet.isEmpty());
    assertTrue(fieldSet.directValues().isEmpty());
    assertTrue(fieldSet.directSubsets().isEmpty());
  }

  @ParameterizedTest
  @MethodSource("nonEmptyFieldSets")
  void isEmpty_whenFieldSetContainsEntries_expectFalse(NodeFieldSet fieldSet) {
    assertFalse(fieldSet.isEmpty());
  }

  @Test
  void constructor_whenSourceMapsMutatedAfterCreation_expectDefensiveCopies() {
    LinkedHashMap<String, String> directValues = new LinkedHashMap<>();
    directValues.put("alpha", "1");
    LinkedHashMap<String, NodeFieldSet> directSubsets = new LinkedHashMap<>();
    directSubsets.put("nested", new NodeFieldSet(Map.of("enabled", "true"), Map.of()));

    NodeFieldSet fieldSet = new NodeFieldSet(directValues, directSubsets);

    directValues.put("alpha", "updated");
    directValues.put("beta", "2");
    directSubsets.clear();

    assertEquals(Map.of("alpha", "1"), fieldSet.directValues());
    assertEquals(
        Map.of("nested", new NodeFieldSet(Map.of("enabled", "true"), Map.of())),
        fieldSet.directSubsets());
  }

  @Test
  void constructor_whenMapsExposed_expectUnmodifiableViews() {
    NodeFieldSet fieldSet =
        new NodeFieldSet(
            Map.of("alpha", "1"), Map.of("nested", new NodeFieldSet(Map.of(), Map.of())));
    Map<String, String> directValues = fieldSet.directValues();
    Map<String, NodeFieldSet> directSubsets = fieldSet.directSubsets();
    NodeFieldSet emptyFieldSet = NodeFieldSet.empty();

    assertThrows(UnsupportedOperationException.class, () -> directValues.put("beta", "2"));
    assertThrows(
        UnsupportedOperationException.class, () -> directSubsets.put("second", emptyFieldSet));
  }

  @Test
  void constructor_whenLinkedHashMapsProvided_expectEncounterOrderPreserved() {
    LinkedHashMap<String, String> directValues = new LinkedHashMap<>();
    directValues.put("alpha", "1");
    directValues.put("beta", "2");
    directValues.put("gamma", "3");
    LinkedHashMap<String, NodeFieldSet> directSubsets = new LinkedHashMap<>();
    directSubsets.put("first", NodeFieldSet.empty());
    directSubsets.put("second", new NodeFieldSet(Map.of("name", "value"), Map.of()));

    NodeFieldSet fieldSet = new NodeFieldSet(directValues, directSubsets);

    assertEquals(
        List.of("alpha", "beta", "gamma"), new ArrayList<>(fieldSet.directValues().keySet()));
    assertEquals(List.of("first", "second"), new ArrayList<>(fieldSet.directSubsets().keySet()));
  }

  @Test
  void constructor_whenDirectValuesNull_expectNullPointerException() {
    Map<String, NodeFieldSet> directSubsets = Map.of();

    assertThrows(NullPointerException.class, () -> new NodeFieldSet(null, directSubsets));
  }

  @Test
  void constructor_whenDirectSubsetsNull_expectNullPointerException() {
    Map<String, String> directValues = Map.of();

    assertThrows(NullPointerException.class, () -> new NodeFieldSet(directValues, null));
  }

  @Test
  void constructor_whenDirectValuesContainNullKey_expectNullPointerException() {
    LinkedHashMap<String, String> directValues = new LinkedHashMap<>();
    directValues.put(null, "value");
    Map<String, NodeFieldSet> directSubsets = Map.of();

    assertThrows(NullPointerException.class, () -> new NodeFieldSet(directValues, directSubsets));
  }

  @Test
  void constructor_whenDirectValuesContainNullValue_expectNullPointerException() {
    LinkedHashMap<String, String> directValues = new LinkedHashMap<>();
    directValues.put("key", null);
    Map<String, NodeFieldSet> directSubsets = Map.of();

    assertThrows(NullPointerException.class, () -> new NodeFieldSet(directValues, directSubsets));
  }

  @Test
  void constructor_whenDirectSubsetsContainNullKey_expectNullPointerException() {
    LinkedHashMap<String, NodeFieldSet> directSubsets = new LinkedHashMap<>();
    directSubsets.put(null, NodeFieldSet.empty());
    Map<String, String> directValues = Map.of();

    assertThrows(NullPointerException.class, () -> new NodeFieldSet(directValues, directSubsets));
  }

  @Test
  void constructor_whenDirectSubsetsContainNullValue_expectNullPointerException() {
    LinkedHashMap<String, NodeFieldSet> directSubsets = new LinkedHashMap<>();
    directSubsets.put("nested", null);
    Map<String, String> directValues = Map.of();

    assertThrows(NullPointerException.class, () -> new NodeFieldSet(directValues, directSubsets));
  }

  private static Stream<NodeFieldSet> nonEmptyFieldSets() {
    return Stream.of(
        new NodeFieldSet(Map.of("enabled", "true"), Map.of()),
        new NodeFieldSet(Map.of(), Map.of("nested", NodeFieldSet.empty())));
  }
}

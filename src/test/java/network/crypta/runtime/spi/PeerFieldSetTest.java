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
class PeerFieldSetTest {

  @Test
  void empty_whenCalled_expectEmptyFieldSet() {
    PeerFieldSet fieldSet = PeerFieldSet.empty();

    assertTrue(fieldSet.isEmpty());
    assertTrue(fieldSet.directValues().isEmpty());
    assertTrue(fieldSet.directSubsets().isEmpty());
  }

  @ParameterizedTest
  @MethodSource("nonEmptyFieldSets")
  void isEmpty_whenFieldSetContainsEntries_expectFalse(PeerFieldSet fieldSet) {
    assertFalse(fieldSet.isEmpty());
  }

  @Test
  void constructor_whenSourceMapsMutatedAfterCreation_expectDefensiveCopies() {
    LinkedHashMap<String, String> directValues = new LinkedHashMap<>();
    directValues.put("alpha", "1");
    LinkedHashMap<String, PeerFieldSet> directSubsets = new LinkedHashMap<>();
    directSubsets.put("nested", new PeerFieldSet(Map.of("enabled", "true"), Map.of()));

    PeerFieldSet fieldSet = new PeerFieldSet(directValues, directSubsets);

    directValues.put("alpha", "updated");
    directValues.put("beta", "2");
    directSubsets.clear();

    assertEquals(Map.of("alpha", "1"), fieldSet.directValues());
    assertEquals(
        Map.of("nested", new PeerFieldSet(Map.of("enabled", "true"), Map.of())),
        fieldSet.directSubsets());
  }

  @Test
  void constructor_whenMapsExposed_expectUnmodifiableViews() {
    PeerFieldSet fieldSet =
        new PeerFieldSet(
            Map.of("alpha", "1"), Map.of("nested", new PeerFieldSet(Map.of(), Map.of())));
    Map<String, String> directValues = fieldSet.directValues();
    Map<String, PeerFieldSet> directSubsets = fieldSet.directSubsets();
    PeerFieldSet emptyFieldSet = PeerFieldSet.empty();

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
    LinkedHashMap<String, PeerFieldSet> directSubsets = new LinkedHashMap<>();
    directSubsets.put("first", PeerFieldSet.empty());
    directSubsets.put("second", new PeerFieldSet(Map.of("name", "value"), Map.of()));

    PeerFieldSet fieldSet = new PeerFieldSet(directValues, directSubsets);

    assertEquals(
        List.of("alpha", "beta", "gamma"), new ArrayList<>(fieldSet.directValues().keySet()));
    assertEquals(List.of("first", "second"), new ArrayList<>(fieldSet.directSubsets().keySet()));
  }

  @Test
  void constructor_whenDirectValuesNull_expectNullPointerException() {
    Map<String, PeerFieldSet> directSubsets = Map.of();

    assertThrows(NullPointerException.class, () -> new PeerFieldSet(null, directSubsets));
  }

  @Test
  void constructor_whenDirectSubsetsNull_expectNullPointerException() {
    Map<String, String> directValues = Map.of();

    assertThrows(NullPointerException.class, () -> new PeerFieldSet(directValues, null));
  }

  @Test
  void constructor_whenDirectValuesContainNullKey_expectNullPointerException() {
    LinkedHashMap<String, String> directValues = new LinkedHashMap<>();
    directValues.put(null, "value");
    Map<String, PeerFieldSet> directSubsets = Map.of();

    assertThrows(NullPointerException.class, () -> new PeerFieldSet(directValues, directSubsets));
  }

  @Test
  void constructor_whenDirectValuesContainNullValue_expectNullPointerException() {
    LinkedHashMap<String, String> directValues = new LinkedHashMap<>();
    directValues.put("key", null);
    Map<String, PeerFieldSet> directSubsets = Map.of();

    assertThrows(NullPointerException.class, () -> new PeerFieldSet(directValues, directSubsets));
  }

  @Test
  void constructor_whenDirectSubsetsContainNullKey_expectNullPointerException() {
    LinkedHashMap<String, PeerFieldSet> directSubsets = new LinkedHashMap<>();
    directSubsets.put(null, PeerFieldSet.empty());
    Map<String, String> directValues = Map.of();

    assertThrows(NullPointerException.class, () -> new PeerFieldSet(directValues, directSubsets));
  }

  @Test
  void constructor_whenDirectSubsetsContainNullValue_expectNullPointerException() {
    LinkedHashMap<String, PeerFieldSet> directSubsets = new LinkedHashMap<>();
    directSubsets.put("nested", null);
    Map<String, String> directValues = Map.of();

    assertThrows(NullPointerException.class, () -> new PeerFieldSet(directValues, directSubsets));
  }

  private static Stream<PeerFieldSet> nonEmptyFieldSets() {
    return Stream.of(
        new PeerFieldSet(Map.of("enabled", "true"), Map.of()),
        new PeerFieldSet(Map.of(), Map.of("nested", PeerFieldSet.empty())));
  }
}

package network.crypta.runtime.spi;

import java.util.EnumMap;
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
class ConfigSnapshotTest {

  @Test
  void empty_whenCalled_expectEmptySnapshot() {
    ConfigSnapshot snapshot = ConfigSnapshot.empty();

    assertTrue(snapshot.isEmpty());
    assertTrue(snapshot.sections().isEmpty());
  }

  @ParameterizedTest
  @MethodSource("nonEmptySnapshots")
  void isEmpty_whenSnapshotContainsNonEmptySection_expectFalse(ConfigSnapshot snapshot) {
    assertFalse(snapshot.isEmpty());
  }

  @Test
  void constructor_whenSectionsContainOnlyEmptyFieldSets_expectEmptySnapshot() {
    ConfigSnapshot snapshot =
        new ConfigSnapshot(
            Map.of(
                ConfigSection.CURRENT,
                ConfigFieldSet.empty(),
                ConfigSection.DEFAULTS,
                ConfigFieldSet.empty()));

    assertTrue(snapshot.isEmpty());
    assertTrue(snapshot.sections().isEmpty());
  }

  @Test
  void
      constructor_whenSectionsContainEmptyAndNonEmptyFieldSets_expectOnlyNonEmptySectionsRetained() {
    ConfigFieldSet current =
        new ConfigFieldSet(Map.of("enabled", "true"), Map.of("node", ConfigFieldSet.empty()));
    ConfigSnapshot snapshot =
        new ConfigSnapshot(
            Map.of(ConfigSection.CURRENT, current, ConfigSection.DEFAULTS, ConfigFieldSet.empty()));

    assertEquals(Map.of(ConfigSection.CURRENT, current), snapshot.sections());
  }

  @Test
  void constructor_whenSourceMapMutatedAfterCreation_expectDefensiveCopy() {
    EnumMap<ConfigSection, ConfigFieldSet> sections = new EnumMap<>(ConfigSection.class);
    ConfigFieldSet current = new ConfigFieldSet(Map.of("enabled", "true"), Map.of());
    sections.put(ConfigSection.CURRENT, current);

    ConfigSnapshot snapshot = new ConfigSnapshot(sections);

    sections.put(ConfigSection.DEFAULTS, new ConfigFieldSet(Map.of("enabled", "false"), Map.of()));
    sections.clear();

    assertEquals(Map.of(ConfigSection.CURRENT, current), snapshot.sections());
  }

  @Test
  void constructor_whenSectionsExposed_expectUnmodifiableView() {
    ConfigFieldSet current = new ConfigFieldSet(Map.of("enabled", "true"), Map.of());
    ConfigSnapshot snapshot = new ConfigSnapshot(Map.of(ConfigSection.CURRENT, current));
    Map<ConfigSection, ConfigFieldSet> sections = snapshot.sections();
    ConfigFieldSet defaults = new ConfigFieldSet(Map.of("enabled", "false"), Map.of());

    assertThrows(
        UnsupportedOperationException.class, () -> sections.put(ConfigSection.DEFAULTS, defaults));
  }

  @Test
  void constructor_whenSectionsNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, () -> new ConfigSnapshot(null));
  }

  @Test
  void constructor_whenSectionsContainNullKey_expectNullPointerException() {
    Map<ConfigSection, ConfigFieldSet> sections =
        new java.util.LinkedHashMap<>(Map.of(ConfigSection.CURRENT, ConfigFieldSet.empty()));
    sections.put(null, ConfigFieldSet.empty());

    assertThrows(NullPointerException.class, () -> new ConfigSnapshot(sections));
  }

  @Test
  void constructor_whenSectionsContainNullValue_expectNullPointerException() {
    Map<ConfigSection, ConfigFieldSet> sections =
        new java.util.LinkedHashMap<>(Map.of(ConfigSection.CURRENT, ConfigFieldSet.empty()));
    sections.put(ConfigSection.DEFAULTS, null);

    assertThrows(NullPointerException.class, () -> new ConfigSnapshot(sections));
  }

  private static Stream<ConfigSnapshot> nonEmptySnapshots() {
    return Stream.of(
        new ConfigSnapshot(
            Map.of(ConfigSection.CURRENT, new ConfigFieldSet(Map.of("enabled", "true"), Map.of()))),
        new ConfigSnapshot(
            Map.of(
                ConfigSection.CURRENT,
                ConfigFieldSet.empty(),
                ConfigSection.DEFAULTS,
                new ConfigFieldSet(Map.of("enabled", "false"), Map.of()))));
  }
}

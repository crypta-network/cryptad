package network.crypta.runtime.spi;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

/**
 * Represents an immutable point-in-time export of runtime configuration sections.
 *
 * <p>A snapshot groups one or more {@link ConfigSection} values with their corresponding
 * hierarchical {@link ConfigFieldSet} payloads. It is the management-facing response object that
 * flows through the runtime SPI after the daemon adapter has exported configuration data and before
 * higher layers serialize that data into a wire-specific form. Keeping this value object in the SPI
 * prevents request handlers from depending on daemon configuration internals.
 *
 * <p>The snapshot is intentionally sparse. It retains only sections that were requested and that
 * produced non-empty content. That keeps responses compact, avoids empty structural noise, and lets
 * callers distinguish between "not requested or empty" and "present with data" by checking the
 * returned map directly.
 *
 * @param sections exported configuration sections keyed by {@link ConfigSection}
 * @see ConfigFieldSet
 * @see ConfigPort
 */
public record ConfigSnapshot(Map<ConfigSection, ConfigFieldSet> sections) {
  /**
   * Creates an immutable snapshot of exported configuration sections.
   *
   * <p>The constructor copies the supplied map into an {@link EnumMap}, rejects {@code null} keys
   * and values, and filters out sections whose field-set payload is empty. Callers may therefore
   * pass a broader intermediate map and rely on the snapshot to normalize it into a compact,
   * immutable view.
   *
   * @param sections section payloads keyed by the exported section name
   * @throws NullPointerException if the map, any section key, or any field-set value is {@code
   *     null}
   */
  public ConfigSnapshot {
    sections = immutableSections(sections);
  }

  /**
   * Returns an empty configuration snapshot.
   *
   * <p>This convenience factory returns a snapshot with no exported sections. It is useful when a
   * caller has no matching data or when a runtime adapter can short-circuit an export request
   * without building an intermediate map.
   *
   * @return empty snapshot with no exported sections
   */
  public static ConfigSnapshot empty() {
    return new ConfigSnapshot(Map.of());
  }

  /**
   * Returns whether the snapshot contains no exported sections.
   *
   * <p>This check reflects the normalized stored state after empty sections have been filtered out
   * by the constructor. A snapshot can therefore be empty either because nothing was requested or
   * because every requested section exported as empty content.
   *
   * @return {@code true} when the snapshot contains no exported sections
   */
  public boolean isEmpty() {
    return sections.isEmpty();
  }

  @Override
  public Map<ConfigSection, ConfigFieldSet> sections() {
    return immutableSections(this.sections);
  }

  private static Map<ConfigSection, ConfigFieldSet> immutableSections(
      Map<ConfigSection, ConfigFieldSet> source) {
    Objects.requireNonNull(source, "sections");
    if (source.isEmpty()) {
      return Map.of();
    }
    EnumMap<ConfigSection, ConfigFieldSet> copy = new EnumMap<>(ConfigSection.class);
    for (Map.Entry<ConfigSection, ConfigFieldSet> entry : source.entrySet()) {
      ConfigSection section = Objects.requireNonNull(entry.getKey(), "sections key");
      ConfigFieldSet fieldSet = Objects.requireNonNull(entry.getValue(), "sections value");
      if (!fieldSet.isEmpty()) {
        copy.put(section, fieldSet);
      }
    }
    return copy.isEmpty() ? Map.of() : Collections.unmodifiableMap(copy);
  }
}

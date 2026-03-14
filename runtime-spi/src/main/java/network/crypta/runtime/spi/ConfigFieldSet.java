package network.crypta.runtime.spi;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Represents one immutable node in a hierarchical configuration field tree.
 *
 * <p>{@code ConfigFieldSet} mirrors the shape of the daemon's legacy field-set export without
 * exposing root-module transport classes through the runtime SPI. Each node stores only the direct
 * scalar values and direct named subsets that appear at that level. Callers can therefore rebuild a
 * nested response structure by walking the tree from the root outward instead of depending on a
 * flattened dotted-key representation.
 *
 * <p>Instances are immutable and safe to share after construction. The constructor copies supplied
 * maps into encounter-order-preserving {@link LinkedHashMap} instances and then exposes
 * unmodifiable views. Empty maps are normalized to shared empty instances so adapters can return
 * compact snapshots without leaking mutability.
 *
 * @param directValues direct scalar values stored at this tree level
 * @param directSubsets direct child subsets keyed by the subset name that appears at this level
 * @see ConfigSnapshot
 */
public record ConfigFieldSet(
    Map<String, String> directValues, Map<String, ConfigFieldSet> directSubsets) {
  /**
   * Creates an immutable tree node from direct values and direct child subsets.
   *
   * <p>The constructor defensively copies both maps, preserves their encounter order where
   * possible, and rejects {@code null} keys and values. Passing empty maps is valid and produces an
   * empty node, but callers should prefer {@link #empty()} when no content exists.
   *
   * @param directValues direct scalar values to store at this tree level
   * @param directSubsets direct child subsets to store at this tree level
   * @throws NullPointerException if either map, any key, or any value is {@code null}
   */
  public ConfigFieldSet {
    directValues = immutableDirectValues(directValues);
    directSubsets = immutableDirectSubsets(directSubsets);
  }

  /**
   * Returns an empty immutable tree node.
   *
   * <p>This is a convenience factory for callers that need a canonical representation of "no direct
   * values and no direct subsets" without allocating mutable maps first.
   *
   * @return empty field-set value with no direct values and no direct subsets
   */
  public static ConfigFieldSet empty() {
    return new ConfigFieldSet(Map.of(), Map.of());
  }

  /**
   * Returns whether this node contains neither direct values nor direct subsets.
   *
   * <p>This is a structural check only. It does not inspect descendant nodes beyond the already
   * stored direct subsets because empty descendant nodes should normally have been filtered before
   * construction by the exporting adapter.
   *
   * @return {@code true} when this node contains no direct values and no direct subsets
   */
  public boolean isEmpty() {
    return directValues.isEmpty() && directSubsets.isEmpty();
  }

  private static Map<String, String> immutableDirectValues(Map<String, String> source) {
    Objects.requireNonNull(source, "directValues");
    if (source.isEmpty()) {
      return Map.of();
    }
    LinkedHashMap<String, String> copy = LinkedHashMap.newLinkedHashMap(source.size());
    for (Map.Entry<String, String> entry : source.entrySet()) {
      copy.put(
          Objects.requireNonNull(entry.getKey(), "directValues key"),
          Objects.requireNonNull(entry.getValue(), "directValues value"));
    }
    return Collections.unmodifiableMap(copy);
  }

  private static Map<String, ConfigFieldSet> immutableDirectSubsets(
      Map<String, ConfigFieldSet> source) {
    Objects.requireNonNull(source, "directSubsets");
    if (source.isEmpty()) {
      return Map.of();
    }
    LinkedHashMap<String, ConfigFieldSet> copy = LinkedHashMap.newLinkedHashMap(source.size());
    for (Map.Entry<String, ConfigFieldSet> entry : source.entrySet()) {
      copy.put(
          Objects.requireNonNull(entry.getKey(), "directSubsets key"),
          Objects.requireNonNull(entry.getValue(), "directSubsets value"));
    }
    return Collections.unmodifiableMap(copy);
  }
}

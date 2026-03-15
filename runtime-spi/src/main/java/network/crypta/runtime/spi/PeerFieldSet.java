package network.crypta.runtime.spi;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Represents one immutable node in a hierarchical peer export tree.
 *
 * <p>{@code PeerFieldSet} mirrors the shape of legacy peer exports and peer-reference trees without
 * exposing daemon-only field-set transport classes through the runtime SPI. Each instance stores
 * only the direct scalar values and direct named subsets that appear at that level. Callers can
 * therefore rebuild a nested response structure by walking the tree from the root outward instead
 * of depending on flattened dotted-key representations.
 *
 * <p>Instances are immutable and safe to share after construction. The constructor copies supplied
 * maps into encounter-order-preserving {@link LinkedHashMap} instances and then exposes
 * unmodifiable views. Empty maps are normalized to shared empty instances so adapters can return
 * compact snapshots without leaking mutability. Callers should treat the record as a detached
 * snapshot value, not as a live view into daemon state.
 *
 * @param directValues direct scalar values stored at this tree level
 * @param directSubsets direct child subsets keyed by the subset name that appears at this level
 * @see PeerSnapshot
 */
public record PeerFieldSet(
    Map<String, String> directValues, Map<String, PeerFieldSet> directSubsets) {
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
  public PeerFieldSet {
    directValues = immutableDirectValues(directValues);
    directSubsets = immutableDirectSubsets(directSubsets);
  }

  /**
   * Returns an empty immutable tree node.
   *
   * <p>This is a convenience factory for callers that need a canonical representation of "no direct
   * values and no direct subsets" without allocating mutable maps first. Export adapters can also
   * use it when optional subsets have been filtered down to nothing.
   *
   * @return empty field-set value with no direct values and no direct subsets
   */
  public static PeerFieldSet empty() {
    return new PeerFieldSet(Map.of(), Map.of());
  }

  /**
   * Returns whether this node contains neither direct values nor direct subsets.
   *
   * <p>This is a structural check only. It does not inspect descendant nodes beyond the already
   * stored direct subsets because empty descendant nodes should normally have been filtered before
   * construction by the exporting adapter. Callers can use the result to decide whether an optional
   * subset should be serialized at all.
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

  private static Map<String, PeerFieldSet> immutableDirectSubsets(
      Map<String, PeerFieldSet> source) {
    Objects.requireNonNull(source, "directSubsets");
    if (source.isEmpty()) {
      return Map.of();
    }
    LinkedHashMap<String, PeerFieldSet> copy = LinkedHashMap.newLinkedHashMap(source.size());
    for (Map.Entry<String, PeerFieldSet> entry : source.entrySet()) {
      copy.put(
          Objects.requireNonNull(entry.getKey(), "directSubsets key"),
          Objects.requireNonNull(entry.getValue(), "directSubsets value"));
    }
    return Collections.unmodifiableMap(copy);
  }
}

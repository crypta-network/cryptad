package network.crypta.runtime.spi;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Represents one immutable node in a hierarchical node-info export tree.
 *
 * <p>{@code NodeFieldSet} mirrors the structure of legacy node-reference exports without exposing
 * daemon-only transport classes through the runtime SPI. Each instance stores only the direct
 * scalar values and direct named subsets at one level, allowing callers to rebuild a wire-specific
 * tree by walking the snapshot recursively.
 *
 * <p>Instances are immutable and safe to share. The constructor defensively copies the supplied
 * maps into encounter-order-preserving {@link LinkedHashMap} instances and then exposes
 * unmodifiable views. Empty maps are normalized to shared empty instances so adapters can return
 * compact snapshots without leaking mutability. Callers should treat the record as a detached
 * snapshot value rather than a live view into the running daemon. Mutating the source maps after
 * construction has no effect on the stored tree, and consumers are expected to walk the tree level
 * by level when rebuilding a transport-specific representation.
 *
 * @param directValues direct scalar values stored at this tree level
 * @param directSubsets direct child subsets keyed by the subset name at this level
 * @see NodeReferenceSnapshot
 */
public record NodeFieldSet(
    Map<String, String> directValues, Map<String, NodeFieldSet> directSubsets) {
  /**
   * Creates an immutable node-info tree node from direct values and direct child subsets.
   *
   * <p>The constructor defensively copies both maps, preserves their encounter order where
   * possible, and rejects {@code null} keys and values. Passing empty maps is valid and produces an
   * empty node, but callers should prefer {@link #empty()} when no content exists.
   *
   * @param directValues direct scalar values to store at this tree level
   * @param directSubsets direct child subsets to store at this tree level
   * @throws NullPointerException if either map, any key, or any value is {@code null}
   */
  public NodeFieldSet {
    directValues = immutableDirectValues(directValues);
    directSubsets = immutableDirectSubsets(directSubsets);
  }

  /**
   * Returns an empty immutable tree node.
   *
   * <p>This is a convenience factory for callers that need a canonical representation of "no direct
   * values and no direct subsets" without allocating mutable maps first. Export adapters can use it
   * when a reference tree or child subset has been filtered down to nothing.
   *
   * @return empty node-info field-set value with no direct values or direct subsets
   */
  public static NodeFieldSet empty() {
    return new NodeFieldSet(Map.of(), Map.of());
  }

  /**
   * Returns whether this node contains neither direct values nor direct subsets.
   *
   * <p>This is a structural check only. It inspects the direct state stored in this node and does
   * not attempt to infer whether a parent or sibling tree still carries meaningful data. Exporters
   * can use the result to omit empty optional subsets such as volatile data when rebuilding a
   * higher-level snapshot.
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

  private static Map<String, NodeFieldSet> immutableDirectSubsets(
      Map<String, NodeFieldSet> source) {
    Objects.requireNonNull(source, "directSubsets");
    if (source.isEmpty()) {
      return Map.of();
    }
    LinkedHashMap<String, NodeFieldSet> copy = LinkedHashMap.newLinkedHashMap(source.size());
    for (Map.Entry<String, NodeFieldSet> entry : source.entrySet()) {
      copy.put(
          Objects.requireNonNull(entry.getKey(), "directSubsets key"),
          Objects.requireNonNull(entry.getValue(), "directSubsets value"));
    }
    return Collections.unmodifiableMap(copy);
  }
}

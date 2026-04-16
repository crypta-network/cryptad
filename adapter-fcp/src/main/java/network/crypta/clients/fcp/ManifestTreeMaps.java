package network.crypta.clients.fcp;

import java.util.HashMap;
import java.util.Map;

/**
 * Provides the smallest adapter-owned map helper needed for legacy manifest-tree traversal.
 *
 * <p>The FCP adapter still stores directory manifests in the long-standing nested shape used by the
 * insert path: directory nodes are mutable {@code Map<String, Object>} instances and leaf entries
 * are {@code ManifestElement} values. Most call sites do not need a rich metadata API to work with
 * those nodes; they only need a safe way to treat an arbitrary object as one of the directory maps.
 * This helper exists to keep that one structural concern inside {@code :adapter-fcp} instead of
 * importing the broader runtime-owned metadata implementation for a simple cast-or-copy operation.
 *
 * <p>The method intentionally preserves mutability. Existing callers recurse into nested maps, free
 * manifest leaves, or rebuild detached entry lists, all of which expect a writable {@code
 * HashMap}-compatible view rather than an immutable wrapper.
 */
final class ManifestTreeMaps {

  /** Utility class; callers use {@link #forceMap(Object)} directly. */
  private ManifestTreeMaps() {}

  /**
   * Returns a mutable {@code Map<String, Object>} view over a nested manifest directory node.
   *
   * <p>If the supplied object is already a {@link HashMap}, the original instance is returned.
   * Other {@link Map} implementations are copied into a new {@link HashMap} after validating that
   * every key is a string.
   *
   * @param value object expected to represent one directory node in a manifest tree
   * @return mutable typed map for the directory node
   * @throws ClassCastException if {@code value} is not a map or any key is not a string
   */
  static Map<String, Object> forceMap(Object value) {
    if (value instanceof HashMap<?, ?> raw) {
      return uncheckedCast(raw);
    }
    if (value instanceof Map<?, ?> map) {
      HashMap<String, Object> typed = new HashMap<>();
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        Object key = entry.getKey();
        if (!(key instanceof String stringKey)) {
          throw new ClassCastException(
              "Expected String keys in map, got "
                  + (key == null ? "null" : key.getClass().getName()));
        }
        typed.put(stringKey, entry.getValue());
      }
      return typed;
    }
    throw new ClassCastException(
        "Expected Map, got " + (value == null ? "null" : value.getClass().getName()));
  }

  /**
   * Performs the unchecked cast used by the fast path for genuine {@link HashMap} instances.
   *
   * <p>The cast is safe under the helper's contract because the caller already identified the value
   * as a legacy manifest directory node. Keeping the cast isolated here avoids repeating the
   * suppression at each call site.
   *
   * @param raw hash map already known to represent one manifest directory node
   * @return the same instance cast to the typed manifest-map view used by the adapter
   */
  @SuppressWarnings("unchecked")
  private static Map<String, Object> uncheckedCast(Map<?, ?> raw) {
    return (Map<String, Object>) raw;
  }
}

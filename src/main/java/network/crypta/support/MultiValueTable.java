package network.crypta.support;

import java.util.*;

import java.util.concurrent.ConcurrentHashMap;

/**
 * A thread-safe multimap storing zero or more values per key.
 *
 * <p>This class provides a simple multi-value table backed by a {@link
 * java.util.concurrent.ConcurrentHashMap} from keys to immutable {@link List}s of values. Reads and
 * updates may run concurrently; updates replace a key's value list atomically with a new immutable
 * list. Methods that expose collections clearly document whether they return live views or
 * immutable snapshots.
 *
 * <p>Nullability and semantics:
 *
 * <ul>
 *   <li>Keys must be non-null; passing a null key throws {@link NullPointerException} (enforced by
 *       {@code ConcurrentHashMap}).
 *   <li>Value elements may be null and are stored as {@code null} entries in the per-key list.
 *   <li>Per-key lists are immutable; callers cannot modify them.
 * </ul>
 *
 * <p>Threading: All public operations are safe for concurrent use without external synchronization.
 * Atomicity is at the key level; for example, {@link #put(Object, Object)} installs a new immutable
 * list for the key in a single {@code Map.compute} operation.
 *
 * @param <K> key type (non-null)
 * @param <V> value element type (elements may be null)
 * @author oskar
 */
public class MultiValueTable<K, V> {
  private final Map<K, List<V>> table;

  /** Creates an empty table with a default initial capacity. */
  public MultiValueTable() {
    table = new ConcurrentHashMap<>();
  }

  /**
   * Creates an empty table with the given initial capacity.
   *
   * @param initialSize expected number of keys; used to size the underlying map
   * @throws IllegalArgumentException if {@code initialSize} is negative
   */
  public MultiValueTable(int initialSize) {
    table = new ConcurrentHashMap<>(initialSize);
  }

  /**
   * Builds a table from parallel arrays of keys and values, pairing entries by index.
   *
   * <p>For duplicated keys, values are appended in encounter order for that key.
   *
   * @param keys keys array; elements must be non-null
   * @param values values array; elements may be null
   * @param <K> key type
   * @param <V> value element type
   * @return a new table containing all pairs
   * @throws IllegalArgumentException if arrays have different lengths
   * @throws NullPointerException if any key is null
   */
  public static <K, V> MultiValueTable<K, V> from(K[] keys, V[] values) {
    if (keys.length != values.length) {
      throw new IllegalArgumentException(
          "keys and values must contain the same number of values, but there are %d keys and %d values"
              .formatted(keys.length, values.length));
    }
    MultiValueTable<K, V> table = new MultiValueTable<>(keys.length);
    for (int i = 0; i < keys.length; i++) {
      table.put(keys[i], values[i]);
    }
    return table;
  }

  /**
   * Builds a single-key table from the given key and vararg values.
   *
   * @param key non-null key
   * @param values values to associate with {@code key}; elements may be null
   * @param <K> key type
   * @param <V> value element type
   * @return a new table with {@code key -> values}
   * @throws NullPointerException if {@code key} is null
   */
  @SafeVarargs
  public static <K, V> MultiValueTable<K, V> from(K key, V... values) {
    return from(key, Arrays.asList(values));
  }

  /**
   * Builds a single-key table from the given key and values collection.
   *
   * @param key non-null key
   * @param values values to associate with {@code key}; elements may be null
   * @param <K> key type
   * @param <V> value element type
   * @return a new table with {@code key -> values}
   * @throws NullPointerException if {@code key} or {@code values} is null
   */
  public static <K, V> MultiValueTable<K, V> from(K key, Collection<? extends V> values) {
    MultiValueTable<K, V> table = new MultiValueTable<>(1);
    table.putAll(key, values);
    return table;
  }

  /**
   * Appends a single value to the list associated with the key.
   *
   * <p>If the key is absent, a new immutable list containing the value is installed. If present, a
   * new immutable list is created by copying the existing list and appending the value, then
   * atomically replacing the old list.
   *
   * @param key non-null key
   * @param value value to append; may be null
   * @throws NullPointerException if {@code key} is null
   */
  public void put(K key, V value) {
    this.table.compute(
        key,
        (k, previousList) -> {
          List<V> result;
          if (previousList == null) {
            // Use ArrayList to preserve null-accepting semantics and predictable growth.
            result = new ArrayList<>(1);
          } else {
            result = new ArrayList<>(previousList.size() + 1);
            result.addAll(previousList);
          }
          result.add(value);
          return Collections.unmodifiableList(result);
        });
  }

  /**
   * Appends all elements to the list associated with the key.
   *
   * <p>Behavior mirrors {@link #put(Object, Object)} but appends an entire collection in one atomic
   * replacement.
   *
   * @param key non-null key
   * @param elements values to append; elements may be null
   * @throws NullPointerException if {@code key} or {@code elements} is null
   */
  public void putAll(K key, Collection<? extends V> elements) {
    this.table.compute(
        key,
        (k, previousList) -> {
          List<V> result;
          if (previousList == null) {
            result = new ArrayList<>(elements.size());
          } else {
            result = new ArrayList<>(previousList.size() + elements.size());
            result.addAll(previousList);
          }
          result.addAll(elements);
          return Collections.unmodifiableList(result);
        });
  }

  /**
   * Returns the first value associated with the key, or {@code null} if none.
   *
   * <p>When the key exists, the first element is the earliest value inserted for that key.
   *
   * @param key non-null key
   * @return first value, or {@code null} when the key is missing or mapped to an empty list
   * @throws NullPointerException if {@code key} is null
   */
  public V getFirst(K key) {
    List<V> list = this.table.get(key);
    if (list == null || list.isEmpty()) {
      return null;
    }
    return list.getFirst();
  }

  /**
   * Returns whether the table contains the key.
   *
   * @param key non-null key
   * @return {@code true} if present; {@code false} otherwise
   * @throws NullPointerException if {@code key} is null
   */
  public boolean containsKey(K key) {
    return this.table.containsKey(key);
  }

  /**
   * Returns the values for a key as an immutable {@link List}.
   *
   * <p>The returned list is the current immutable list installed for the key and will not reflect
   * later changes: subsequent {@link #put(Object, Object)} or {@link #putAll(Object, Collection)}
   * calls for the same key install a new list and leave previously returned lists unchanged.
   *
   * @param key non-null key
   * @return immutable list of values; {@link Collections#emptyList()} if the key is absent
   * @throws NullPointerException if {@code key} is null
   */
  public List<V> getAllAsList(K key) {
    return this.table.getOrDefault(key, Collections.emptyList());
  }

  /**
   * Returns an {@link Iterable} view of the current values for a key.
   *
   * <p>This is equivalent to {@link #getAllAsList(Object)} and is convenient for enhanced {@code
   * for} loops. The underlying list is immutable and does not reflect later changes for the key.
   *
   * @param key non-null key
   * @return iterable over the current immutable list
   * @throws NullPointerException if {@code key} is null
   */
  public Iterable<V> iterateAll(K key) {
    return getAllAsList(key);
  }

  /**
   * Returns the number of values currently associated with the key.
   *
   * @param key non-null key
   * @return value count for the key (zero when absent)
   * @throws NullPointerException if {@code key} is null
   */
  public int countAll(K key) {
    return getAllAsList(key).size();
  }

  /**
   * Removes all values for the key.
   *
   * @param key non-null key
   * @throws NullPointerException if {@code key} is null
   */
  public void remove(K key) {
    this.table.remove(key);
  }

  /**
   * Returns whether the table has no keys.
   *
   * @return {@code true} if empty; {@code false} otherwise
   */
  public boolean isEmpty() {
    return this.table.isEmpty();
  }

  /**
   * Returns the number of distinct keys currently in the table.
   *
   * @return key count
   */
  public int size() {
    return this.table.size();
  }

  /**
   * Removes all keys and values.
   *
   * <p>This operation is atomic with respect to individual key mappings but does not block
   * concurrent reads.
   */
  public void clear() {
    this.table.clear();
  }

  /**
   * Removes a single occurrence of {@code value} from the list for {@code key}, if present.
   *
   * <p>When the removal empties the list, the key is removed from the table.
   *
   * @param key non-null key
   * @param value value to remove; a {@code null} value removes a {@code null} element if present
   * @return {@code true} if an element was removed, {@code false} otherwise
   * @throws NullPointerException if {@code key} is null
   */
  @SuppressWarnings("UnusedReturnValue")
  public boolean removeElement(K key, V value) {
    boolean[] removed = new boolean[1];
    this.table.computeIfPresent(
        key,
        (k, previousList) -> {
          if (!previousList.contains(value)) {
            return previousList;
          }
          List<V> result = new ArrayList<>(previousList.size() - 1);
          for (V v : previousList) {
            if (Objects.equals(v, value) && !removed[0]) {
              removed[0] = true;
            } else {
              result.add(v);
            }
          }
          if (result.isEmpty()) {
            // Returning null to Map.computeIfPresent removes the mapping.
            return null;
          }
          return Collections.unmodifiableList(result);
        });
    return removed[0];
  }

  /**
   * Returns an immutable snapshot of the current key set.
   *
   * <p>The returned set cannot be modified and does not reflect later changes to the table.
   *
   * @return immutable snapshot of keys
   */
  public Set<K> keySet() {
    // Java 10+: returns an unmodifiable snapshot of current keys.
    return Set.copyOf(this.table.keySet());
  }

  /**
   * Returns an immutable snapshot of all values across all keys.
   *
   * <p>Order is the concatenation of per-key lists in the map's iteration order. The returned
   * collection is independent of subsequent updates.
   *
   * @return immutable snapshot of all values
   */
  public Collection<V> values() {
    List<V> allValues = new ArrayList<>();
    for (List<V> entryValues : this.table.values()) {
      allValues.addAll(entryValues);
    }
    return Collections.unmodifiableList(allValues);
  }

  /**
   * Returns an immutable snapshot of the table entries.
   *
   * <p>The returned set contains unmodifiable {@link Map.Entry} instances; calling {@link
   * Map.Entry#setValue(Object)} throws {@link UnsupportedOperationException}. The snapshot does not
   * reflect subsequent updates to the table.
   *
   * @return immutable snapshot of entries with unmodifiable values lists
   */
  public Set<Map.Entry<K, List<V>>> entrySet() {
    // Snapshot as an unmodifiable set of unmodifiable entries.
    // Use Map.entry(...) to ensure Map.Entry#setValue is unsupported.
    Set<Map.Entry<K, List<V>>> snapshot = HashSet.newHashSet(this.table.size());
    for (Map.Entry<K, List<V>> e : this.table.entrySet()) {
      snapshot.add(Map.entry(e.getKey(), e.getValue()));
    }
    return Collections.unmodifiableSet(snapshot);
  }

  /**
   * Returns a human-readable representation intended for diagnostics.
   *
   * @return string representation including the backing map
   */
  @Override
  public String toString() {
    return "[MultiValueTable table=" + table + "]";
  }
}

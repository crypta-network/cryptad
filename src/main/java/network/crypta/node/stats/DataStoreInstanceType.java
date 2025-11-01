package network.crypta.node.stats;

/**
 * Immutable descriptor identifying a single logical data store instance.
 *
 * <p>A {@code DataStoreInstanceType} pairs a {@link DataStoreKeyType} key type with a {@link
 * DataStoreType} store type to describe which class of keys is kept in which kind of store (for
 * example, {@code CHK} entries in the main {@code STORE}, or {@code SSK} entries in the {@code
 * CACHE}). Code that aggregates statistics, maintains per-store counters, or routes operations can
 * use this value object as a compact, strongly-typed identifier.
 *
 * <p>The class is immutable and value-based: two instances are equal when both their key type and
 * store type are equal. This makes it safe to use as a key in maps or as an element in sets. The
 * {@link #hashCode()} implementation combines both components, and {@link #toString()} produces a
 * concise human-readable representation helpful for logging and diagnostics.
 *
 * <ul>
 *   <li><strong>Immutability:</strong> both fields are {@code final}; instances are thread-safe.
 *   <li><strong>Identity:</strong> equality and hash code derive from key and store only.
 *   <li><strong>Typical use:</strong> grouping measurements or selecting per-store behavior.
 * </ul>
 *
 * <pre>{@code
 * // Example: create a descriptor for CHK entries in the main store
 * var id = new DataStoreInstanceType(DataStoreKeyType.CHK, DataStoreType.STORE);
 * }</pre>
 *
 * @see DataStoreKeyType
 * @see DataStoreType
 */
public class DataStoreInstanceType {
  /**
   * Store category that holds the entries for this instance. Values include main store, cache,
   * slashdot, and client-specific stores. The value never changes after construction and is
   * suitable for use in equality and hashing.
   */
  public final DataStoreType store;

  /**
   * Key category indicating which kind of keys populate the addressed store. Typical values are
   * {@code CHK}, {@code SSK}, or public key variants. The value is immutable and participates in
   * equality and hashing semantics.
   */
  public final DataStoreKeyType key;

  /**
   * Creates a new descriptor that uniquely identifies a combination of key type and store type.
   *
   * <p>The resulting object is immutable and value-based. It can be safely shared across threads
   * and used as a key in hash-based collections. Neither argument may be {@code null}; callers
   * should pass explicit enum values reflecting the targeted store and key domain.
   *
   * @param key the {@link DataStoreKeyType} describing the kind of keys kept in the store; must be
   *     a non-null enum value such as {@code CHK} or {@code SSK} that matches the intended domain
   *     of entries.
   * @param store the {@link DataStoreType} indicating which storage category is addressed; must be
   *     a non-null enum value such as {@code STORE}, {@code CACHE}, or other supported variants.
   */
  public DataStoreInstanceType(DataStoreKeyType key, DataStoreType store) {
    this.store = store;
    this.key = key;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    DataStoreInstanceType that = (DataStoreInstanceType) o;

    if (key != that.key) return false;
    return store == that.store;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    int result = store.hashCode();
    result = 31 * result + key.hashCode();
    return result;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "DataStoreInstanceType{" + "store=" + store + ", key=" + key + '}';
  }
}

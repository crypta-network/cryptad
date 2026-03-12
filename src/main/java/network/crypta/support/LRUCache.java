package network.crypta.support;

/**
 * A small, fixed-capacity, least-recently-used (LRU) cache with an optional per-entry expiration
 * time.
 *
 * <p>On insertion or update, the entry becomes most-recently-used. When the cache exceeds its size
 * limit, the least-recently-used entries are evicted to make room. Lookups that find a live entry
 * promote it to most-recently-used; lookups that find an expired entry remove it and behave as if
 * the entry were absent.
 *
 * <p>Expiration is evaluated against {@link System#currentTimeMillis()} when entries are created
 * and when they are retrieved via {@link #get}. Expired entries are only purged on access (or when
 * they are evicted for capacity reasons); there is no background or periodic garbage collection in
 * this implementation. This cache is therefore intended for small capacities (or for holding many
 * small items) where opportunistic cleanup is acceptable. If a larger cache is required, consider
 * an alternative that includes scheduled cleanup.
 *
 * <p>Operations delegate to {@link LRUMap}, which uses a tree-based map to avoid hash-collision
 * denial-of-service scenarios. Typical {@code put} and {@code get} are {@code O(log N)} due to the
 * underlying {@code TreeMap}.
 *
 * <p>Thread-safety: this class does not provide external synchronization guarantees. Callers should
 * synchronize externally if using the same instance from multiple threads.
 *
 * <p>Nullability: keys must be non-null (a {@link NullPointerException} is thrown by {@link
 * LRUMap}); values may be null. A stored {@code null} value is indistinguishable from an absent or
 * expired entry when using {@link #get}.
 *
 * @param <K> key type; must be {@link Comparable}
 * @param <V> value type
 * @author xor (xor@freenetproject.org)
 */
public final class LRUCache<K extends Comparable<K>, V> {

  private final int mSizeLimit;
  private final long mExpirationDelay;

  // Holds the cached value and its absolute expiration deadline (in epoch milliseconds).
  private final class Entry {
    private final V mValue;
    private final long mExpirationDate;

    /** Records the value and computes the absolute expiration deadline. */
    public Entry(final V myValue) {
      mValue = myValue;
      mExpirationDate =
          (mExpirationDelay < Long.MAX_VALUE)
              ? (System.currentTimeMillis() + mExpirationDelay)
              : Long.MAX_VALUE;
    }

    /** Returns whether the entry is expired at the given wall-clock time. */
    public boolean expired(final long time) {
      return mExpirationDate < time;
    }

    /** Returns whether the entry is expired at the current wall-clock time. */
    public boolean expired() {
      return expired(System.currentTimeMillis());
    }

    public V getValue() {
      return mValue;
    }
  }

  private final LRUMap<K, Entry> mCache;

  /**
   * Constructs a cache with the given capacity and no expiration.
   *
   * <p>Entries never expire (unless evicted for capacity) because the expiration delay is set to
   * {@link Long#MAX_VALUE}.
   *
   * @param sizeLimit maximum number of entries held at once. Values greater than zero store up to
   *     that many entries; zero means every insertion immediately evicts and the cache remains
   *     effectively empty.
   */
  public LRUCache(final int sizeLimit) {
    mCache = LRUMap.createSafeMap();
    mSizeLimit = sizeLimit;
    mExpirationDelay = Long.MAX_VALUE;
  }

  /**
   * Constructs a cache with the given capacity and expiration policy.
   *
   * <p>Each inserted or updated entry receives a deadline equal to {@code
   * System.currentTimeMillis() + expirationDelay}. The deadline is checked on retrieval. Negative
   * delays cause entries to be considered expired immediately.
   *
   * @param sizeLimit maximum number of entries held at once
   * @param expirationDelay delay in milliseconds from insertion/update until an entry expires; use
   *     {@link Long#MAX_VALUE} for no expiration
   */
  public LRUCache(final int sizeLimit, final long expirationDelay) {
    mCache = LRUMap.createSafeMap();
    mSizeLimit = sizeLimit;
    mExpirationDelay = expirationDelay;
  }

  // Evicts least-recently-used entries until there is at least {@code capacity} free space.
  // Precondition: capacity <= size limit (asserted below). The loop removes from the tail (LRU)
  // until the size invariant is restored.
  @SuppressWarnings("SameParameterValue")
  private void freeCapacity(final int capacity) {
    assert (capacity <= mSizeLimit);

    final int limit = mSizeLimit - capacity;
    while (mCache.size() > limit) mCache.popValue();
  }

  /**
   * Inserts or updates an entry and promotes it to most-recently-used.
   *
   * <p>If the key already exists, the value is replaced and the expiration deadline is recomputed
   * from the current wall-clock time using this cache's expiration delay. If inserting causes the
   * size limit to be exceeded, the least-recently-used entries are evicted.
   *
   * @param key non-null key
   * @param value value to store (may be null)
   * @throws NullPointerException if {@code key} is null
   */
  public void put(final K key, final V value) {
    mCache.push(key, new Entry(value));
    freeCapacity(0);
  }

  /**
   * Retrieves the value for a key and promotes the entry to most-recently-used.
   *
   * <p>If the key has no mapping or if the mapping is expired at retrieval time, this returns
   * {@code null}. When an expired entry is encountered, it is removed. If a {@code null} value was
   * stored, this method also returns {@code null} and the result is indistinguishable from the
   * "absent or expired" case.
   *
   * @param key non-null key
   * @return the stored value, or {@code null} if absent or expired
   * @throws NullPointerException if {@code key} is null
   */
  public V get(final K key) {
    final Entry entry = mCache.get(key);
    if (entry == null) return null;

    if (mExpirationDelay < Long.MAX_VALUE && entry.expired()) {
      mCache.removeKey(key);
      return null;
    }

    // Promote to most-recently-used ordering.
    mCache.push(key, entry);

    return entry.getValue();
  }

  /**
   * Removes all entries from the cache.
   *
   * <p>This clears current contents but does not change the size limit or expiration policy; future
   * operations use the same configuration.
   */
  public void clear() {
    mCache.clear();
  }
}

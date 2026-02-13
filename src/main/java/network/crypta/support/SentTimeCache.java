package network.crypta.support;

import java.io.Serial;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Bounded cache that maps sequence numbers to their "sent" timestamps.
 *
 * <p>The cache stores, for each sequence number, the time (in milliseconds since the epoch) at
 * which it was reported as sent. Capacity is fixed at construction time. When the capacity is
 * exceeded, entries are evicted on a first-in first-out basis according to insertion order. When an
 * existing sequence number is reported again, its associated time is updated but its position in
 * the eviction order does not change.
 *
 * <p>Thread-safety: All public methods are synchronized on {@code this}, providing simple mutual
 * exclusion for concurrent use. Calls are atomic with respect to each other.
 *
 * <p>Expected complexity: All operations are O(1) on average, backed by a {@link LinkedHashMap}.
 *
 * @author bertm
 */
public class SentTimeCache {

  /**
   * Fixed-capacity, insertion-ordered {@link LinkedHashMap} for {@code int}-to-{@code long}
   * mappings. Used internally by {@link SentTimeCache} to implement FIFO eviction.
   */
  private static final class BoundedSentTimeMap extends LinkedHashMap<Integer, Long> {
    @Serial private static final long serialVersionUID = 0;
    private final int maxSize;

    /**
     * Constructs a map with the given maximum (and initial) size.
     *
     * @param maxSize maximum number of entries this map may contain; must be positive
     * @throws IllegalArgumentException if {@code maxSize <= 0}
     */
    BoundedSentTimeMap(int maxSize) {
      super(maxSize);
      if (maxSize <= 0) {
        throw new IllegalArgumentException("Negative or zero maxSize");
      }
      this.maxSize = maxSize;
    }

    /**
     * Automatically maintains the maximum size by returning true if the capacity is exceeded,
     * indicating that the eldest entry must be removed.
     *
     * @see LinkedHashMap#removeEldestEntry(Map.Entry)
     */
    @Override
    protected boolean removeEldestEntry(Map.Entry<Integer, Long> eldest) {
      // Be explicit about which size() is referenced in this inner class that extends
      // LinkedHashMap to avoid any ambiguity with methods on the outer class.
      return super.size() > maxSize;
    }

    @Override
    public boolean equals(Object obj) {
      // Preserve default identity/entry-based semantics from LinkedHashMap.
      return super.equals(obj);
    }

    @Override
    public int hashCode() {
      // Preserve default identity/entry-based semantics from LinkedHashMap.
      return super.hashCode();
    }
  }

  /** The inner cache. */
  private final BoundedSentTimeMap cache;

  /**
   * Constructs a cache with the given capacity.
   *
   * @param maxSize maximum number of sequence numbers the cache retains; must be positive
   * @throws IllegalArgumentException if {@code maxSize <= 0}
   */
  public SentTimeCache(int maxSize) {
    cache = new BoundedSentTimeMap(maxSize);
  }

  /**
   * Records that the given sequence number was sent at the specified time.
   *
   * <p>If the cache is full, this call evicts the eldest entry (FIFO by insertion order). If the
   * sequence number already exists, its time is updated to {@code time} without affecting eviction
   * order.
   *
   * <p>Thread-safety: synchronized on {@code this}.
   *
   * @param seqnum sequence number to record
   * @param time sent time in milliseconds since the epoch; negative values are accepted
   */
  public synchronized void report(int seqnum, long time) {
    cache.put(seqnum, time);
  }

  /**
   * Convenience wrapper around {@link #report(int, long)} that uses the current wall-clock time.
   *
   * <p>The time source is {@link System#currentTimeMillis()}. Capacity and eviction semantics are
   * identical to {@link #report(int, long)}.
   *
   * <p>Thread-safety: synchronized on {@code this}.
   *
   * @param seqnum sequence number to record
   * @see SentTimeCache#report(int, long)
   */
  public synchronized void sent(int seqnum) {
    long time = System.currentTimeMillis();
    report(seqnum, time);
  }

  /**
   * Returns and removes the sent time associated with the given sequence number.
   *
   * <p>Removal is unconditional when the entry exists. If the sequence number is absent, this
   * method returns {@code -1}.
   *
   * <p>Thread-safety: synchronized on {@code this}.
   *
   * @param seqnum sequence number to query
   * @return the associated time in milliseconds since the epoch, or {@code -1} if absent
   */
  public synchronized long queryAndRemove(int seqnum) {
    Long ret = cache.remove(seqnum);
    if (ret == null) {
      return -1;
    }
    return ret;
  }

  /**
   * Returns the current number of entries held by the cache.
   *
   * <p>Thread-safety: synchronized on {@code this}.
   *
   * @return number of entries
   */
  synchronized int size() {
    return cache.size();
  }
}

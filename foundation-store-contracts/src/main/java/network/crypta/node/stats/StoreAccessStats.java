package network.crypta.node.stats;

/**
 * Summarizes read/write access statistics for a data store.
 *
 * <p>Instances of this abstract type expose read-oriented counters (hits, misses, false positives)
 * and write counters as observed by a particular store. Implementations typically back these values
 * with thread-safe counters updated by the store’s I/O path and may compute derived rates from the
 * exposed primitives. The contract is deliberately minimal, so it can model both in-memory caches
 * and persistent stores with different eviction and validation strategies.
 *
 * <p>The methods are intended for metrics dashboards, admin endpoints, and diagnostics. Values
 * represent point-in-time readings; they may change between calls. Implementations should be safe
 * to query concurrently from multiple threads without additional synchronization requirements.
 * Derived methods such as {@link #successRate()} document their preconditions and failure modes to
 * avoid conflating "no data" with a meaningful rate.
 *
 * <ul>
 *   <li>Use the primitive counters for precise alerting and long-term trends.
 *   <li>Prefer rates for visualizing traffic patterns; calibrate for your deployment scale.
 *   <li>Handle unavailability explicitly (for example, at a startup or with empty histories).
 * </ul>
 *
 * @see network.crypta.node.stats.StatsNotAvailableException
 */
public abstract class StoreAccessStats {
  /**
   * Initializes the statistics container for subclass implementations.
   *
   * <p>This constructor exists so that the default, no-argument constructor is explicitly
   * documented. The class is abstract and cannot be instantiated directly; the constructor is
   * invoked only by subclasses.
   */
  protected StoreAccessStats() {}

  /**
   * Returns the number of successful read requests (cache hits or equivalent).
   *
   * <p>This counter increases when a requested object can be satisfied from the store without
   * fallback work. The exact definition of a hit depends on the store type (for example, direct
   * lookup success for caches, or validated presence for persistent stores).
   *
   * @return non-negative count of read hits observed so far; monotonically non-decreasing per
   *     process unless counters are reset by the implementation.
   */
  public abstract long hits();

  /**
   * Returns the number of read requests that could not be served directly by the store.
   *
   * <p>A miss typically implies that an upstream fetch, recomputation, or alternative path was
   * required. For persistent stores, a miss may indicate true absence; for caches, it commonly
   * leads to a refill.
   *
   * @return non-negative count of read misses observed so far; monotonically non-decreasing per
   *     process unless counters are reset by the implementation.
   */
  public abstract long misses();

  /**
   * Returns the number of false positives detected during lookups.
   *
   * <p>False positives generally occur when a preliminary test (such as a probabilistic filter)
   * indicates presence, yet the object is not retrievable. This counter helps assess filter tuning
   * and its impact on unnecessary follow-on work.
   *
   * @return non-negative count of false positives observed so far; monotonically non-decreasing per
   *     process unless counters are reset by the implementation.
   */
  public abstract long falsePos();

  /**
   * Returns the number of write operations issued to the store.
   *
   * <p>Depending on the store, a writing may represent an insert, update, or a completed fill after
   * a miss. The counter reflects successfully issued writes; failures may or may not be included
   * based on implementation policy.
   *
   * @return non-negative count of writes observed so far; monotonically non-decreasing per process
   *     unless counters are reset by the implementation.
   */
  public abstract long writes();

  /**
   * Returns the total number of read requests seen by the store.
   *
   * <p>Computed as {@code hits() + misses()}. This is a convenience method used for rate
   * calculations and basic throughput charts.
   *
   * @return non-negative count of read requests; equals the sum of hits and misses.
   */
  public long readRequests() {
    return hits() + misses();
  }

  /**
   * Returns the number of successful reads, or zero when no reads have occurred yet.
   *
   * <p>This avoids implying success when no traffic has been observed. Prefer this method over
   * directly calling {@link #hits()} when rendering early-startup states.
   *
   * @return non-negative count of successful reads; zero when {@link #readRequests()} is zero.
   */
  public long successfulReads() {
    if (readRequests() > 0) return hits();
    else return 0;
  }

  /**
   * Returns the read success rate as a percentage of total reads.
   *
   * <p>Calculated as {@code (100.0 * hits() / readRequests())}. When no reads have been observed
   * yet, the rate is undefined, and this method signals unavailability rather than returning a
   * value that could be misinterpreted.
   *
   * @return a percentage in the range {@code [0.0, 100.0]} when at least one read has been
   *     observed. The exact rounding behavior follows IEEE-754 double arithmetic.
   * @throws StatsNotAvailableException if {@link #readRequests()} is zero and a rate would be
   *     undefined.
   */
  public double successRate() throws StatsNotAvailableException {
    if (readRequests() > 0) return (100.0 * hits() / readRequests());
    else throw new StatsNotAvailableException();
  }

  /**
   * Returns the average read request rate per second for the node uptime period.
   *
   * <p>Computed as {@code readRequests() / nodeUptimeSeconds}. Callers should pass a strictly
   * positive uptime. If zero is supplied, the result follows IEEE-754 semantics (for example,
   * {@code Infinity} or {@code NaN}) and should not be used for alerting.
   *
   * @param nodeUptimeSeconds total node uptime in seconds over which to average; must be greater
   *     than zero for a meaningful finite rate.
   * @return average reads per second as a double; the value may be fractional.
   */
  public double accessRate(long nodeUptimeSeconds) {
    return (1.0 * readRequests() / nodeUptimeSeconds);
  }

  /**
   * Returns the average writing rate per second for the node uptime period.
   *
   * <p>Computed as {@code writes() / nodeUptimeSeconds}. As with {@link #accessRate(long)}, callers
   * should provide a strictly positive uptime to avoid undefined ratios at startup.
   *
   * @param nodeUptimeSeconds total node uptime in seconds over which to average; must be greater
   *     than zero for a meaningful finite rate.
   * @return average writes per second as a double; the value may be fractional.
   */
  public double writeRate(long nodeUptimeSeconds) {
    return (1.0 * writes() / nodeUptimeSeconds);
  }
}

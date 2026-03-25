package network.crypta.node.stats;

import network.crypta.store.StoreCallback;

/**
 * Adapter that exposes a {@link StoreCallback} and companion location metrics as {@link
 * DataStoreStats}.
 *
 * <p>Instances of this class present a read-only, aggregated view of an underlying store's capacity
 * and access behavior together with network-location statistics. The adapter obtains the
 * storage-specific counters (key count, maximum keys, element size) from the provided {@link
 * StoreCallback} and delegates locality/"distance" metrics to a {@link StoreLocationStats}
 * provider. This makes it suitable for administrative dashboards, telemetry exporters, and other
 * diagnostics that expect the unified {@link DataStoreStats} contract.
 *
 * <p>The adapter is intentionally lightweight and performs no background sampling. Values reflect
 * the moment they are queried and may change between calls as the node processes requests. The
 * access-statistics fields are captured from the delegate at construction time so the caller can
 * obtain stable references for the current process session and, when supported by the store, the
 * all-time or persisted totals.
 *
 * <ul>
 *   <li>Thread-safety: instances are immutable after construction and safe for concurrent reads.
 *   <li>Units: counts are expressed in <em>keys</em>; size derives from {@link
 *       StoreCallback#dataLength()} and therefore shares its unit (typically bytes per entry).
 *   <li>Division by zero: methods that compute ratios (for example, {@link #utilization()}) follow
 *       IEEE-754 semantics; callers should handle {@code NaN} or infinities at startup.
 * </ul>
 *
 * @see DataStoreStats
 * @see StoreAccessStats
 * @see StoreLocationStats
 * @author nikotyan
 */
public class StoreCallbackStats implements DataStoreStats {

  private final StoreCallback<?> storeStats;
  private final StoreLocationStats nodeStats;

  /**
   * Access statistics scoped to the current process session.
   *
   * <p>This reference is captured from the delegate callback during construction so listeners have
   * a stable handle for the lifetime of the adapter. Implementations typically reset session stats
   * on node restart. The referenced object is expected to be thread-safe for reads.
   */
  public final StoreAccessStats sessionAccessStats;

  /**
   * Access statistics accumulated across sessions or persisted by the store when available.
   *
   * <p>If the store type does not support long-horizon totals, this field is {@code null}. In that
   * case {@link #getTotalAccessStats()} throws {@link StatsNotAvailableException} to avoid
   * producing misleading values. When non-null, the referenced object is expected to be thread-safe
   * for reads.
   */
  public final StoreAccessStats totalAccessStats;

  /**
   * Creates a new adapter that delegates storage counters and access stats to the given callback
   * and locality metrics to the supplied location-stats provider.
   *
   * @param delegate store-specific adapter providing counters, sizes, and access metrics; must not
   *     be {@code null} and should remain valid for the lifetime of this instance.
   * @param nodeStats provider of location and distance metrics associated with the same store; must
   *     not be {@code null} and may throw when statistics are temporarily unavailable.
   */
  public StoreCallbackStats(StoreCallback<?> delegate, StoreLocationStats nodeStats) {
    this.storeStats = delegate;
    this.nodeStats = nodeStats;
    this.sessionAccessStats = delegate.getSessionAccessStats();
    this.totalAccessStats = delegate.getTotalAccessStats();
  }

  /**
   * Returns the number of keys currently tracked by the underlying store.
   *
   * @return a non-negative count of entries at the time of the call; may change as background work
   *     proceeds.
   */
  @Override
  public long keys() {
    return storeStats.keyCount();
  }

  /**
   * Returns the configured capacity limit, expressed in keys, for the underlying store.
   *
   * @return the maximum number of keys the store is configured to hold; implementations may choose
   *     sentinel values for unbounded stores.
   */
  @Override
  public long capacity() {
    return storeStats.getMaxKeys();
  }

  /**
   * Returns the aggregate data size implied by the current key count.
   *
   * <p>The value is computed as {@code keys() * delegate.dataLength()}. It reflects a logical size
   * defined by the block type and does not include headers or metadata unless the callback's data
   * length encodes them.
   *
   * @return an implementation-defined size unit consistent with {@link StoreCallback#dataLength()}.
   */
  @Override
  public long dataSize() {
    return keys() * storeStats.dataLength();
  }

  /**
   * Delegates to the provided {@link StoreLocationStats} to report the average location metric.
   *
   * @return a double representing the average location over the provider's sampling window.
   * @throws StatsNotAvailableException if the location statistics are not available at call time.
   */
  @Override
  public double avgLocation() throws StatsNotAvailableException {
    return nodeStats.avgLocation();
  }

  /**
   * Returns the utilization of the store as a ratio of keys to capacity.
   *
   * <p>Computed as {@code 1.0 * keys() / capacity()}. At startup or when capacity is zero, the
   * result follows IEEE-754 semantics ({@code NaN} or infinities) and should be treated accordingly
   * by callers.
   *
   * @return a ratio in {@code [0.0, 1.0]} under normal operation; see notes for exceptional cases.
   */
  @Override
  public double utilization() {
    return (1.0 * keys() / capacity());
  }

  /**
   * Delegates to {@link StoreLocationStats} to report an average success indicator.
   *
   * @return a double summarizing success over a provider-defined window or history.
   * @throws StatsNotAvailableException if success data cannot be produced at this time.
   */
  @Override
  public double avgSuccess() throws StatsNotAvailableException {
    return nodeStats.avgSuccess();
  }

  /**
   * Delegates to {@link StoreLocationStats} to report the most distant successful operation.
   *
   * @return a double representing the provider-defined distance of the furthest success.
   * @throws StatsNotAvailableException if distance or success samples are unavailable.
   */
  @Override
  public double furthestSuccess() throws StatsNotAvailableException {
    return nodeStats.furthestSuccess();
  }

  /**
   * Delegates to {@link StoreLocationStats} to report the average distance metric.
   *
   * @return a double representing the provider-defined average distance across observed samples.
   * @throws StatsNotAvailableException if distance statistics are not currently available.
   */
  @Override
  public double avgDist() throws StatsNotAvailableException {
    return nodeStats.avgDist();
  }

  /**
   * Delegates to {@link StoreLocationStats} to report a composite distance statistic.
   *
   * @return a double capturing an implementation-defined characteristic of the distance
   *     distribution (for example, variance or a trimmed measure).
   * @throws StatsNotAvailableException if the distribution cannot be computed or sampled.
   */
  @Override
  public double distanceStats() throws StatsNotAvailableException {
    return nodeStats.distanceStats();
  }

  /**
   * Returns the per-session access statistics captured at construction time.
   *
   * @return a thread-safe {@link StoreAccessStats} view representing access behavior for the
   *     current process session; the reference is stable for this adapter's lifetime.
   */
  @Override
  public StoreAccessStats getSessionAccessStats() {
    return sessionAccessStats;
  }

  /**
   * Returns access statistics accumulated beyond the current session when supported.
   *
   * <p>If the underlying store does not provide total access metrics, this method signals
   * unavailability via an exception to avoid conflating "unknown" with a meaningful value.
   *
   * @return a thread-safe {@link StoreAccessStats} view representing long-horizon or persisted
   *     access behavior.
   * @throws StatsNotAvailableException if the store does not support total access statistics.
   */
  @Override
  public StoreAccessStats getTotalAccessStats() throws StatsNotAvailableException {
    if (totalAccessStats == null) throw new StatsNotAvailableException();
    return totalAccessStats;
  }
}

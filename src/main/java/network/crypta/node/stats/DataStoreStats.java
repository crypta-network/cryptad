package network.crypta.node.stats;

/**
 * Provides aggregate statistics for a specific instance of a data store.
 *
 * <p>Implementations expose summary counters and derived metrics that are suitable for publishing
 * in administrative dashboards, telemetry collectors, or troubleshooting tools. Typical consumers
 * poll these values periodically to visualize utilization trends, capacity headroom, and
 * effectiveness of lookups or insertions. The interface does not prescribe units for every metric;
 * where units are not obvious, they are explicitly documented as implementation-defined so
 * deployments can select representations that best match their storage model (for example, entries,
 * bytes, or logical capacity).
 *
 * <p>Methods that depend on live sampling may temporarily be unavailable and signal this via {@link
 * StatsNotAvailableException}. The interface itself is read-only; implementations should be safe to
 * invoke concurrently from multiple threads. Values are snapshots at the time of the call and may
 * change between invocations, especially in busy nodes. For short-lived sessions, the session
 * access metrics offer a focused view, while the total access metrics can include persisted or
 * long-horizon aggregates when supported.
 *
 * <ul>
 *   <li>Use for dashboards, alerting inputs, and periodic telemetry exports.
 *   <li>Interpret values comparatively over time; avoid hard-coding absolute thresholds without
 *       calibration.
 *   <li>Handle {@code StatsNotAvailableException} gracefully to cover startup and shutdown windows.
 * </ul>
 *
 * @see network.crypta.node.stats.StoreAccessStats
 * @see network.crypta.node.stats.StoreLocationStats
 * @see network.crypta.node.stats.DataStoreType
 * @see network.crypta.node.stats.DataStoreKeyType
 * @author nikotyan
 */
public interface DataStoreStats {
  /**
   * Returns the number of keys or entries currently tracked by the store.
   *
   * <p>The exact meaning of a “key” can vary across implementations (for example, content chunks or
   * identity-scoped records). The returned value is non-negative and reflects a point-in-time view
   * that may change as background maintenance or client requests progress.
   *
   * @return the current count of stored entries; the unit is implementation-defined but consistent
   *     within a given deployment and store type.
   */
  long keys();

  /**
   * Returns the logical capacity of the store according to its configuration.
   *
   * <p>Capacity can represent a maximum number of entries, a byte budget, or another limit
   * depending on the storage engine and policy. Unbounded stores may report a sentinel value as
   * defined by the implementation.
   *
   * @return the configured capacity limit in implementation-defined units; non-negative when a
   *     limit is enforced.
   */
  long capacity();

  /**
   * Returns the size of data currently held by the store.
   *
   * <p>Implementations commonly report bytes on disk or in memory, but alternate units are
   * permitted. Use this together with {@link #capacity()} and {@link #utilization()} to understand
   * growth over time and headroom for new data.
   *
   * @return the current data size in an implementation-defined unit; non-negative and monotonic
   *     between immediate successive calls only in the absence of deletions or compaction.
   */
  long dataSize();

  /**
   * Returns the store utilization as a normalized fraction when available.
   *
   * <p>Utilization represents how much of the configured capacity is currently in use. The value is
   * typically in the range {@code [0.0, 1.0]} but implementations may choose a different scale if
   * appropriate. Prefer reading this metric alongside {@link #capacity()} and {@link #dataSize()}
   * to obtain a complete picture.
   *
   * @return a utilization value representing used capacity relative to the configured limit; the
   *     scale is implementation-defined but consistent per implementation and version.
   */
  double utilization();

  /**
   * Returns the average observed location metric for recent operations.
   *
   * <p>The definition of location is implementation-specific (for example, a position in a logical
   * key or node space). The average is aggregated over a recent window or all-time and is intended
   * for relative comparison within the same deployment.
   *
   * @return a double representing the average location across samples; units and scale are
   *     implementation-defined and should be interpreted with companion metrics.
   * @throws StatsNotAvailableException if the location samples are not available at this time (for
   *     example, during startup, shutdown, or when statistics are disabled).
   */
  double avgLocation() throws StatsNotAvailableException;

  /**
   * Returns an average success indicator for operations attributed to this store.
   *
   * <p>Implementations may compute this as a ratio, probability estimate, or smoothed metric over a
   * defined period. Treat this as a directional indicator; use longer-term trends for alerts.
   *
   * @return a double summarizing success over the chosen window; units and bounds are
   *     implementation-defined and may be normalized.
   * @throws StatsNotAvailableException if success data cannot be produced at call time.
   */
  double avgSuccess() throws StatsNotAvailableException;

  /**
   * Returns a metric for the most distant successful operation in the observed period.
   *
   * <p>This highlights tail behavior relative to the implementation’s distance notion and helps
   * identify outliers or long routing paths that still succeed.
   *
   * @return a double representing the distance of the furthest successful operation; units and
   *     normalization are implementation-defined.
   * @throws StatsNotAvailableException if distance or success samples are unavailable.
   */
  double furthestSuccess() throws StatsNotAvailableException;

  /**
   * Returns the average distance metric across recent operations.
   *
   * <p>Distance is defined by the implementation (for example, difference in a logical key space)
   * and the average may be computed over a sliding window with optional smoothing.
   *
   * @return a double representing the average distance; interpretation requires context from the
   *     same implementation and configuration.
   * @throws StatsNotAvailableException if distance statistics are not currently available.
   */
  double avgDist() throws StatsNotAvailableException;

  /**
   * Returns a composite distance statistic that summarizes distribution characteristics.
   *
   * <p>Providers may expose a moment (such as variance), a trimmed statistic, or another derived
   * value capturing the shape of the distance distribution, complementing the simple average.
   *
   * @return a double capturing a composite or higher-order property of the distance distribution;
   *     semantics are implementation-defined and intended for relative comparison.
   * @throws StatsNotAvailableException if the underlying distribution cannot be sampled or computed
   *     at this time.
   */
  double distanceStats() throws StatsNotAvailableException;

  /**
   * Returns access statistics for the current process session.
   *
   * <p>Session access stats typically reset on node restart and are useful for debugging short-term
   * behaviors without historical carryover. Implementations should ensure this method never throws
   * and instead report empty/zeroed metrics when inactive.
   *
   * @return a {@link StoreAccessStats} instance representing access patterns for the current
   *     process lifetime; returned objects are read-only snapshots or views depending on
   *     implementation.
   */
  StoreAccessStats getSessionAccessStats();

  /**
   * Returns access statistics aggregated across the full lifetime of the store when supported.
   *
   * <p>Depending on configuration, this may include persisted history or long-horizon aggregates.
   * Some implementations may not retain such data and will signal unavailability.
   *
   * @return a {@link StoreAccessStats} instance representing long-horizon or total access behavior;
   *     immutability guarantees are implementation-specific.
   * @throws StatsNotAvailableException if total access statistics are not recorded or cannot be
   *     retrieved at this time.
   */
  StoreAccessStats getTotalAccessStats() throws StatsNotAvailableException;
}

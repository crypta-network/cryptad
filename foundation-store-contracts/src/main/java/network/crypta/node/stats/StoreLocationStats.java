package network.crypta.node.stats;

/**
 * Exposes aggregate location/distance success metrics for a data store.
 *
 * <p>Implementations provide summary statistics that describe how requests associated with a given
 * store distribute over the network "location" space and how successful those requests are. The
 * exact definitions of <em>location</em> and <em>distance</em> depend on the store and routing
 * algorithm in use; values are typically normalized to implementation-defined units so they can be
 * compared within the same deployment. Callers should treat these numbers as descriptive indicators
 * useful for trend analysis and health dashboards rather than strict SLAs.
 *
 * <p>Methods may throw {@link StatsNotAvailableException} during initialization, shutdown, or when
 * statistics are disabled. The interface is read-only; implementations must be safe to invoke from
 * multiple threads concurrently. Returned values represent snapshots at call time and do not imply
 * any guarantees about future behavior.
 *
 * <ul>
 *   <li>Use to visualize locality and routing efficacy for a store.
 *   <li>Integrate into periodic telemetry collectors or admin endpoints.
 *   <li>Prefer coarse-grained alerts; avoid tight control loops on single readings.
 * </ul>
 *
 * @see network.crypta.node.stats.DataStoreStats
 * @see network.crypta.node.stats.DataStoreType
 * @see network.crypta.node.stats.StatsNotAvailableException
 * @author nikotyan
 */
public interface StoreLocationStats {

  /**
   * Returns the average observed location metric for recent store operations.
   *
   * <p>The location metric is defined by the implementation and may represent a position in a
   * logical key space or node space. The average aggregates over a recent window or all-time,
   * depending on the provider. Callers must not assume specific bounds or a particular
   * normalization; compare values produced by the same implementation and version.
   *
   * @return a double representing the average location across observed samples; the unit and scale
   *     are implementation-defined and should be interpreted relative to companion metrics.
   * @throws StatsNotAvailableException if the provider cannot compute the metric at this time, for
   *     example during initialization, shutdown, or when statistics collection is disabled.
   */
  double avgLocation() throws StatsNotAvailableException;

  /**
   * Returns the average success metric for requests attributed to this store.
   *
   * <p>Implementations may compute this as a ratio, a percentile, or a smoothed probability over a
   * defined period. Consumers should treat it as a directional indicator of effective success
   * rather than an exact probability unless the implementation explicitly documents otherwise.
   *
   * @return a double summarizing success over the chosen window; exact units and bounds depend on
   *     the implementation and may be normalized or smoothed.
   * @throws StatsNotAvailableException if success data is not currently available or the subsystem
   *     producing it is inactive.
   */
  double avgSuccess() throws StatsNotAvailableException;

  /**
   * Returns a metric describing the most distant successful retrieval or write.
   *
   * <p>This value highlights the furthest point in the measured period at which an operation still
   * succeeded according to the implementation’s notion of distance. It is useful for spotting
   * outliers and understanding the tail behavior of routing or lookup paths.
   *
   * @return a double representing the distance of the furthest successful operation; units and
   *     normalization are implementation-defined and intended for relative comparison.
   * @throws StatsNotAvailableException if distance/success samples are unavailable or incomplete at
   *     call time.
   */
  double furthestSuccess() throws StatsNotAvailableException;

  /**
   * Returns the average distance metric across observed operations.
   *
   * <p>The distance is measured according to the implementation’s definition (for example,
   * difference in a logical key space). The average is typically computed over a sliding window and
   * may employ smoothing. Consumers should interpret changes over time rather than rely on absolute
   * thresholds unless they are calibrated for a specific deployment.
   *
   * @return a double representing the average distance across samples; interpretation requires
   *     context from the same implementation and configuration.
   * @throws StatsNotAvailableException if distance statistics cannot be produced at this time.
   */
  double avgDist() throws StatsNotAvailableException;

  /**
   * Returns a composite distance statistic summarizing distribution characteristics.
   *
   * <p>Depending on the provider this may be a moment (e.g., variance), a trimmed statistic, or
   * another summary value derived from the underlying distance distribution. It complements the
   * simple average with additional shape information for dashboards and anomaly detection.
   *
   * @return a double capturing a composite or higher-order property of the distance distribution;
   *     semantics are implementation-defined and should be used for relative comparison.
   * @throws StatsNotAvailableException if the underlying distribution cannot be computed or sampled
   *     at this time.
   */
  double distanceStats() throws StatsNotAvailableException;
}

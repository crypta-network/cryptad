package network.crypta.node.stats;

/**
 * Store stats placeholder used when aggregate location metrics are not available.
 *
 * <p>This implementation of {@link StoreLocationStats} represents a data store (or a runtime
 * situation) where location-/distance-based statistics cannot be produced. Typical reasons include
 * stores that do not track such metrics, components that are still initializing or shutting down,
 * or deployments where statistics collection is disabled. Every method throws {@link
 * StatsNotAvailableException} to make the absence of data explicit and to prevent consumers from
 * misinterpreting missing samples as zero or default values.
 *
 * <p>Use this class as a safe, explicit sentinel in places where a stats object is required by the
 * API but no measurements are possible. Callers should catch the exception and fall back to
 * coarse-grained health indicators or omit the affected widgets. The class is stateless and
 * thread-safe; instances can be reused across threads without synchronization.
 *
 * <ul>
 *   <li>Provides a consistent signaling mechanism for unavailable metrics.
 *   <li>Avoids returning partial or misleading values during lifecycle transitions.
 *   <li>Encourages callers to handle unavailability as a normal, recoverable condition.
 * </ul>
 *
 * @see StoreLocationStats
 * @see StatsNotAvailableException
 * @author nikotyan
 */
public class NotAvailNodeStoreStats implements StoreLocationStats {
  /**
   * Constructs a stats placeholder that always signals unavailability.
   *
   * <p>The class is stateless; constructing multiple instances has no observable effect beyond
   * allocating objects. Prefer reusing a single instance where convenient.
   */
  public NotAvailNodeStoreStats() {
    // Intentionally empty: this placeholder is stateless and requires no initialization.
  }

  /**
   * Always throws because the average location metric is not available for this store.
   *
   * <p>This sentinel implementation does not compute or retain location samples. Callers should
   * catch the exception and either retry later, display an "unavailable" state, or skip rendering
   * this metric.
   *
   * @return never returns; the method always throws.
   * @throws StatsNotAvailableException unconditionally, to indicate the metric cannot be provided
   *     by this implementation.
   */
  @Override
  public double avgLocation() throws StatsNotAvailableException {
    throw new StatsNotAvailableException();
  }

  /**
   * Always throws because the average success metric is not available for this store.
   *
   * <p>No success history is maintained by this implementation. Treat this as a normal, expected
   * condition for stores that do not expose success ratios.
   *
   * @return never returns; the method always throws.
   * @throws StatsNotAvailableException unconditionally, to indicate the metric cannot be provided
   *     by this implementation.
   */
  @Override
  public double avgSuccess() throws StatsNotAvailableException {
    throw new StatsNotAvailableException();
  }

  /**
   * Always throws because the furthest success distance is not available for this store.
   *
   * <p>Distance-based tail behavior is not tracked by this implementation. Callers should display a
   * placeholder or omit the metric when this exception is raised.
   *
   * @return never returns; the method always throws.
   * @throws StatsNotAvailableException unconditionally, to indicate the metric cannot be provided
   *     by this implementation.
   */
  @Override
  public double furthestSuccess() throws StatsNotAvailableException {
    throw new StatsNotAvailableException();
  }

  /**
   * Always throws because the average distance metric is not available for this store.
   *
   * <p>This implementation does not record or compute distance values. Consumers should handle this
   * exception as a benign unavailability signal.
   *
   * @return never returns; the method always throws.
   * @throws StatsNotAvailableException unconditionally, to indicate the metric cannot be provided
   *     by this implementation.
   */
  @Override
  public double avgDist() throws StatsNotAvailableException {
    throw new StatsNotAvailableException();
  }

  /**
   * Always throws because composite distance statistics are not available for this store.
   *
   * <p>Higher-order distribution metrics (such as variance or percentiles) are not computed by this
   * implementation. Prefer summarizing available counters or indicating that distance stats are
   * unavailable.
   *
   * @return never returns; the method always throws.
   * @throws StatsNotAvailableException unconditionally, to indicate the metric cannot be provided
   *     by this implementation.
   */
  @Override
  public double distanceStats() throws StatsNotAvailableException {
    throw new StatsNotAvailableException();
  }
}

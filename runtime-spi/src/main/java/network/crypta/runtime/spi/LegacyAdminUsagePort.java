package network.crypta.runtime.spi;

/**
 * Supplies detached legacy-admin usage counters to diagnostics surfaces.
 *
 * <p>The port is optional for Platform API callers. Runtime-only test routers and non-HTTP hosts
 * can omit it, while the legacy HTTP admin adapter can provide an implementation backed by its
 * in-memory request recorder. The API shape stays JDK-only and deliberately exposes process-local
 * counters rather than a persistent audit trail.
 *
 * <p>The interface is intentionally read-only. Implementations own the recording policy, including
 * which requests count as accepted usage and which surfaces are safe to report. Diagnostics callers
 * only ask for a snapshot and serialize it; they should not infer access decisions or try to record
 * traffic through this SPI.
 *
 * <p>Implementations should return quickly and avoid blocking on disk or network I/O. The current
 * legacy HTTP implementation is in-memory, and future implementations should preserve that
 * expectation unless the diagnostics API is explicitly redesigned for persisted telemetry.
 *
 * @see LegacyAdminUsageSnapshot
 */
public interface LegacyAdminUsagePort {
  /**
   * Returns one point-in-time snapshot of process-local legacy-admin usage counters.
   *
   * <p>The snapshot should be safe for callers to retain after the method returns. Implementations
   * may continue recording new observations concurrently, but those later observations should not
   * mutate the returned object.
   *
   * @return immutable snapshot of known legacy admin surfaces and their observed counts
   */
  LegacyAdminUsageSnapshot snapshot();
}

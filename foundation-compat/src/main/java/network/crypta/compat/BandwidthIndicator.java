package network.crypta.compat;

/**
 * Provides estimated network throughput values used by setup and configuration heuristics.
 *
 * <p>Implementations expose a lightweight, pull-based view of currently available bandwidth for
 * downstream and upstream directions. Callers typically query this interface while initializing
 * node defaults or guiding user-facing bandwidth choices, where an approximate rate is more useful
 * than precise telemetry. The contract intentionally avoids prescribing sampling methodology:
 * values may come from system APIs, persisted measurements, or conservative static estimates.
 *
 * <p>Returned rates are expressed as bits per second and are expected to be non-negative. The
 * interface is read-only and stateless; thread-safety and caching behavior are implementation
 * concerns.
 *
 * <ul>
 *   <li><b>Primary use:</b> feed first-run bandwidth recommendation logic.
 *   <li><b>Design trade-off:</b> low-overhead approximate values over continuous monitoring.
 * </ul>
 */
public interface BandwidthIndicator {
  /**
   * Returns the estimated maximum downstream transfer rate.
   *
   * <p>This value represents the current best-effort estimate of inbound link capacity that setup
   * logic can use to derive receive-side limits. Implementations may return either live-probed or
   * cached values, so callers should treat the result as advisory rather than exact. A value of
   * zero usually means unavailable or effectively no measurable downstream capacity.
   *
   * @return estimated downstream maximum bandwidth in bits per second
   */
  int getDownstreamMaxBitRate();

  /**
   * Returns the estimated maximum upstream transfer rate.
   *
   * <p>This value represents the current best-effort estimate of outbound link capacity for use in
   * upload-related defaults and throttling hints. Because sampling strategies vary by
   * implementation, the number should be interpreted as an approximation suitable for policy
   * decisions, not strict accounting. A zero result indicates that no usable estimate is available.
   *
   * @return estimated upstream maximum bandwidth in bits per second
   */
  int getUpstreamMaxBitRate();
}

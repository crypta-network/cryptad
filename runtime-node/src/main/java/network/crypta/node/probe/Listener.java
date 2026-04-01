package network.crypta.node.probe;

/**
 * Listener for probe results emitted by the probing subsystem.
 *
 * <p>Implementations receive callbacks when a peer supplies a specific piece of information (for
 * example bandwidth limit, build number, or location) or when an error/refusal occurs. A single
 * probe may yield zero or more of these callbacks depending on the request type and the outcome on
 * the responding node. Methods are independent: callers invoke only those that correspond to the
 * requested metric or terminal condition.
 *
 * <p>Threading and ordering are defined by the caller; implementations that coordinate shared state
 * should therefore be thread-safe and tolerate out-of-order delivery. Returned values may be
 * intentionally perturbed (for example with Gaussian noise) to protect privacy; consumers should
 * treat them as approximate rather than exact measurements.
 *
 * <ul>
 *   <li>Receives one-shot terminal signals: {@link #onError(Error, Byte, boolean)} and {@link
 *       #onRefused()}.
 *   <li>Receives metric results such as {@link #onOutputBandwidth(float)}, {@link #onBuild(int)},
 *       {@link #onIdentifier(long, byte)}, and {@link #onOverallBulkOutputCapacity(byte, float)}.
 * </ul>
 *
 * @see Error
 */
public interface Listener {
  /**
   * Reports that the probe finished with an error.
   *
   * <p>The error categorizes the failure condition (for example timeout or overload). When present,
   * {@code code} conveys a raw, implementation-defined byte that may accompany {@code UNKNOWN} or
   * {@code UNRECOGNIZED_TYPE} to allow diagnostics. The {@code local} flag distinguishes failures
   * originating on the current node from those relayed from a remote peer. Implementations should
   * treat this callback as terminal for the current probe and release any per-probe resources they
   * hold.
   *
   * @param error the specific {@link Error} that describes the failure category; never {@code
   *     null}.
   * @param code optional raw error code associated with {@code UNKNOWN} or similar cases; {@code
   *     null} when not applicable or when no code was provided by the peer.
   * @param local {@code true} when the failure originated locally; {@code false} when propagated
   *     from a remote node that processed the request.
   */
  void onError(Error error, Byte code, boolean local);

  /**
   * Indicates that the endpoint explicitly refused to provide the requested information.
   *
   * <p>This is a terminal outcome distinct from errors and successful metric results. Refusals may
   * reflect local policy, privacy settings, or rate limiting on the responding node.
   */
  void onRefused();

  /**
   * Output bandwidth limit result.
   *
   * <p>Represents the peer's configured outbound bandwidth cap. Values may be noisy and are
   * expressed in kibibytes per second (KiB/s). Consumers should avoid treating this as a precise
   * measurement and instead use it for coarse classification or display.
   *
   * @param outputBandwidth endpoint's reported output bandwidth limit in KiB per second;
   *     non-negative; implementations should treat the value as approximate rather than exact.
   */
  void onOutputBandwidth(float outputBandwidth);

  /**
   * Build result.
   *
   * <p>Provides the build number (or main version integer) reported by the responding node. This is
   * primarily useful for compatibility checks, diagnostics, and UI display, and does not uniquely
   * identify a binary beyond the scope of the project's versioning scheme.
   *
   * @param build endpoint's reported build or main version number as an integer; non-negative in
   *     typical deployments.
   */
  void onBuild(int build);

  /**
   * Identifier result.
   *
   * <p>Provides a long-lived node identifier chosen by the peer, together with a coarse quantized
   * weekly uptime percentage. The uptime value is intentionally noisy to protect peer privacy. The
   * identifier is not guaranteed to be globally unique and should not be used as a security token;
   * it exists to support heuristic matching and troubleshooting.
   *
   * @param identifier identifier supplied by the endpoint; format and stability are implementation
   *     defined and may change between restarts unless otherwise documented by the caller.
   * @param uptimePercentage quantized, noisy seven-day uptime percentage in the range 0–100; higher
   *     values indicate more availability but exact precision is not guaranteed.
   */
  void onIdentifier(long identifier, byte uptimePercentage);

  /**
   * Link length result.
   *
   * <p>Supplies link-length statistics as reported by the peer. The array represents an
   * implementation-defined summary and may be perturbed; consumers should not assume a particular
   * histogram shape or binning without consulting the caller that initiated the probe.
   *
   * @param linkLengths endpoint's reported link-length values; the array is owned by the caller and
   *     should be treated as read-only by listeners. Units and indexing are implementation-defined.
   */
  void onLinkLengths(float[] linkLengths);

  /**
   * Location result.
   *
   * <p>Reports the node's position within the routing space. The numeric value is a
   * single-precision float whose interpretation (scale, wrap-around behavior) is defined by the
   * routing algorithm in use and may be approximate.
   *
   * @param location location value supplied by the endpoint; semantics are implementation-defined
   *     and should be interpreted in the context of the routing layer.
   */
  void onLocation(float location);

  /**
   * Store size result.
   *
   * <p>Indicates the peer's datastore size. The value is typically derived from on-disk
   * configuration or measurement and is multiplied by noise before disclosure. Use for rough
   * capacity estimation, not for precise accounting.
   *
   * @param storeSize endpoint's reported store size in GiB (gibibytes), multiplied by Gaussian
   *     noise; treat as an approximate value rather than an exact capacity figure.
   */
  void onStoreSize(float storeSize);

  /**
   * Uptime result.
   *
   * <p>Provides a noisy percentage of the peer's uptime over the requested window (48 hours or
   * seven days). The value ranges from 0 to 100 and may include small perturbations for privacy.
   *
   * @param uptimePercentage endpoint's reported uptime percentage in the last requested period
   *     (either 48 hours or seven days); value in the range 0–100, subject to noise.
   */
  void onUptime(float uptimePercentage);

  /**
   * Reject stats.
   *
   * <p>Conveys coarse rejection rates (bulk only) for recent operations. Values are percentages and
   * may be negative to signal insufficient data. Consumers should handle short histories and
   * rounding effects gracefully.
   *
   * @param stats array of four bytes: percentage rejections for (bulk only) CHK request, SSK
   *     request, CHK insert, and SSK insert, in that order. A negative value indicates insufficient
   *     data; a non-negative value expresses a percentage.
   */
  void onRejectStats(byte[] stats);

  /**
   * Capacity usage and approximate bandwidth class.
   *
   * <p>Supplies two related metrics: a severely truncated bandwidth class and an approximate
   * overall bulk output capacity usage. The bandwidth class is a small ordinal derived from the
   * peer's configured limit via the protocol's bandwidth-class mapping; the usage is a unit-less
   * fraction that may be noisy. Together they allow coarse, privacy-preserving comparisons of peers
   * without exposing exact throughput.
   *
   * @param bandwidthClassForCapacityUsage ordinal bandwidth class in a small inclusive range (for
   *     coarse grouping); derived from the peer's outbound limit.
   * @param capacityUsage noisy overall bulk output capacity usage as a unit-less fraction in the
   *     range 0.0–1.0; values may exceed the range slightly due to noise and should be clamped when
   *     displayed.
   */
  void onOverallBulkOutputCapacity(byte bandwidthClassForCapacityUsage, float capacityUsage);
}

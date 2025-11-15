package network.crypta.clients.fcp;

/**
 * Streams probe feedback about the client's bulk output utilization back to the endpoint that
 * requested the measurement.
 *
 * <p>This response is emitted by the node whenever it finishes executing the {@code
 * OverallBulkOutputCapacityUsage} probe. The class keeps the payload intentionally tiny—just the
 * optional FCP identifier plus two scalar metrics—so the node can instantiate and serialize it
 * immediately inside latency-sensitive I/O threads. Instances are short-lived and are not meant to
 * be retained beyond the outbound write cycle. Callers interact with the inherited {@link
 * network.crypta.support.SimpleFieldSet} directly to push the serialized values onto the wire.
 *
 * <p>The class is not thread-safe: each response should be assembled and written on a single thread
 * without handoff. Consumers generally configure the identifier if they need to correlate responses
 * to outstanding requests; otherwise the identifier may be omitted (null). Both numeric fields are
 * stored verbatim so downstream tooling can interpret the bandwidth class and usage ratios without
 * additional transformation.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> capture probe metadata, expose the canonical message
 *       name, and host the probe metrics inside the shared field set.
 *   <li><strong>Notable behavior:</strong> the class performs no validation and assumes callers
 *       already normalized the sampled metrics.
 * </ul>
 */
public class ProbeOverallBulkOutputCapacityUsage extends FCPResponse {

  /**
   * Creates a response that links an optional FCP identifier with the measured capacity usage
   * figures reported by the probe.
   *
   * <p>The constructor synchronously stores the identifier (if non-null) and writes both the
   * bandwidth class byte and the floating-point usage ratio into the inherited field set. No
   * validation or clamping occurs because the caller is expected to pass sanitized probe output.
   * The resulting instance is ready for immediate serialization, and callers should avoid further
   * mutation once the response is queued for transmission to prevent race conditions on the shared
   * {@link network.crypta.support.SimpleFieldSet} reference.
   *
   * <pre>{@code
   * var response = new ProbeOverallBulkOutputCapacityUsage(id, (byte) 2, 0.67f);
   * connection.write(response.getName(), response.getFieldSet());
   * }</pre>
   *
   * @param identifier Optional correlation token supplied by the requesting client; pass {@code
   *     null} to emit an anonymous event when correlation is unnecessary.
   * @param bandwidthClassForCapacityUsage Byte describing the throttling class that governed the
   *     sampling period; values map to the protocol's bandwidth classes and are stored verbatim.
   * @param capacityUsage Floating-point ratio in the {@code [0, +Inf)} range representing how much
   *     bulk output capacity the client currently consumes relative to its allowance.
   */
  public ProbeOverallBulkOutputCapacityUsage(
      String identifier, byte bandwidthClassForCapacityUsage, float capacityUsage) {
    super(identifier);
    fs.put(OUTPUT_BANDWIDTH_CLASS, bandwidthClassForCapacityUsage);
    fs.put(OVERALL_BULK_OUTPUT_CAPACITY_USAGE, capacityUsage);
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return "ProbeOverallBulkOutputCapacityUsage";
  }
}

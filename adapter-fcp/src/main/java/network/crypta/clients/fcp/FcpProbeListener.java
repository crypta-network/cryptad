package network.crypta.clients.fcp;

/**
 * Adapter-owned listener for probe callbacks delivered back into the FCP message layer.
 *
 * <p>{@link ProbeRequest} uses this listener as the adapter-visible contract for receiving probe
 * results and terminal failures. The interface mirrors the runtime probe callback surface closely
 * enough that the bridge layer can translate events with minimal policy, but it remains owned by
 * {@code :adapter-fcp} so message classes no longer depend directly on runtime probe types. Each
 * callback corresponds to a concrete FCP response shape or terminal control path.
 *
 * <p>Implementations are typically short-lived and bound to one inbound FCP request. Callbacks may
 * arrive asynchronously on whatever threading model the underlying network subsystem uses.
 * Implementers should not assume caller affinity. They should not rely on a mutable shared state
 * without synchronization. They should also preserve the distinction between terminal errors,
 * refusals, and successful result payloads. The listener itself does not impose retry or
 * deduplication policy; it simply receives translated probe events.
 *
 * <ul>
 *   <li>Owns the adapter-side vocabulary for all currently supported probe outcomes.
 *   <li>Lets the bridge map runtime callbacks back into FCP responses without leaking runtime APIs.
 *   <li>Assumes request-scoped implementations rather than long-lived shared observers.
 * </ul>
 *
 * @see ProbeRequest
 * @see FcpMessageRuntimeSupport#startProbe(byte, long, FcpProbeType, FcpProbeListener)
 */
public interface FcpProbeListener {

  /**
   * Reports that the probe finished with an error.
   *
   * <p>This callback represents a terminal failure path. The probe will not subsequently report a
   * successful value result for the same request. Implementations should usually translate the
   * event directly into a {@link ProbeError} response, preserving the adapter-owned error category,
   * optional raw code, and locality flag so clients can distinguish local failures from remote
   * verdicts.
   *
   * @param error adapter-owned error category describing the terminal failure and never {@code
   *     null}.
   * @param code optional raw probe error code preserved for wire-compatible serialization when the
   *     runtime exposes one; {@code null} when no extra numeric code applies.
   * @param local whether the failure originated on the local node rather than being relayed from a
   *     remote peer.
   */
  void onError(FcpProbeError error, Byte code, boolean local);

  /**
   * Reports that the probe was refused before a value result was produced.
   *
   * <p>This is distinct from {@link #onError(FcpProbeError, Byte, boolean)} because refusal is a
   * first-class protocol outcome with its own FCP response type. Implementations should treat it as
   * terminal for the current request unless the surrounding runtime explicitly documents otherwise.
   */
  void onRefused();

  /**
   * Reports the probe's output bandwidth result.
   *
   * <p>This callback delivers the probe result for bandwidth-oriented requests. Implementations
   * should preserve the reported numeric value as-is when converting it into the corresponding FCP
   * response so clients see the same float precision and units that the runtime supplied.
   *
   * @param outputBandwidth reported output bandwidth value from the runtime probe subsystem.
   */
  void onOutputBandwidth(float outputBandwidth);

  /**
   * Reports the probe's build result.
   *
   * <p>The reported build number is the runtime value returned by the probe target and should
   * generally be forwarded unchanged into the adapter response message.
   *
   * @param build reported build number for the probed node or route endpoint.
   */
  void onBuild(int build);

  /**
   * Reports the probe's identifier result.
   *
   * <p>This callback delivers both the probed identifier and the associated uptime percentage that
   * goes with that result shape. Implementations should preserve the pairing rather than treating
   * either value as independently optional.
   *
   * @param probeIdentifier reported probe identifier value supplied by the runtime probe result.
   * @param percentageUptime reported percentage uptime associated with the identifier result.
   */
  void onIdentifier(long probeIdentifier, byte percentageUptime);

  /**
   * Reports the probe's link-lengths result.
   *
   * <p>The array contents are already arranged in the runtime-provided order. Implementations
   * should preserve that ordering when encoding the eventual FCP response and should not mutate the
   * array unless they first copy it for defensive isolation.
   *
   * @param linkLengths reported link-length values for the current probe result and never {@code
   *     null}.
   */
  void onLinkLengths(float[] linkLengths);

  /**
   * Reports the probe's location result.
   *
   * <p>This callback carries the location value exactly as reported by the runtime probe path. It
   * is typically forwarded directly into the matching FCP response message.
   *
   * @param location reported location value for the completed probe request.
   */
  void onLocation(float location);

  /**
   * Reports the probe's datastore size result.
   *
   * <p>The datastore size value is already normalized according to the runtime probe subsystem's
   * conventions. Implementations should preserve the float value as supplied instead of applying
   * adapter-local rounding or formatting decisions here.
   *
   * @param storeSize reported datastore size value for the completed probe request.
   */
  void onStoreSize(float storeSize);

  /**
   * Reports the probe's uptime result.
   *
   * <p>This callback carries the runtime-reported uptime percentage for the selected probe type.
   * Implementations should forward the value directly and let the response serializer decide how it
   * appears on the wire.
   *
   * @param uptimePercent reported uptime percentage for the completed probe request.
   */
  void onUptime(float uptimePercent);

  /**
   * Reports the probe's reject-stats result.
   *
   * <p>The statistics array is a structured payload whose element ordering is part of the runtime
   * result contract. Implementations should preserve that ordering and byte values when converting
   * the result into the FCP response representation.
   *
   * @param stats reported reject-statistics payload for the completed probe request and never
   *     {@code null}.
   */
  void onRejectStats(byte[] stats);

  /**
   * Reports the probe's overall bulk output capacity usage result.
   *
   * <p>This callback carries both the coarse bandwidth class used for grouping and the associated
   * capacity-usage value. Implementations should preserve the pairing because the class provides
   * the context clients need to interpret the reported usage number correctly.
   *
   * @param bandwidthClassForCapacityUsage reported bandwidth class used for coarse capacity
   *     grouping in the runtime probe result.
   * @param capacityUsage reported overall bulk output capacity usage value associated with that
   *     bandwidth class.
   */
  void onOverallBulkOutputCapacity(byte bandwidthClassForCapacityUsage, float capacityUsage);
}

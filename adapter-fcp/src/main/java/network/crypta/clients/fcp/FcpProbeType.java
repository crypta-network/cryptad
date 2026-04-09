package network.crypta.clients.fcp;

/**
 * Adapter-owned enumeration of probe types accepted by FCP probe messages.
 *
 * <p>This enum is the adapter-side vocabulary for probe requests and probe result routing. Its
 * constant names intentionally match the long-standing FCP {@code Type} field values so that
 * parsing and serialization remain wire-compatible even though the message layer no longer imports
 * the runtime-owned probe type enum directly. The bridge layer is responsible for translating these
 * adapter-visible names into whatever runtime representation the live daemon currently expects.
 *
 * <p>Only the protocol-stable names belong here. Runtime numeric codes, hop routing behavior, and
 * probe execution policy remain outside the adapter leaf. That separation keeps FCP parsing logic
 * easy to reason about while letting the runtime evolve behind a narrow conversion boundary.
 *
 * @see ProbeRequest
 * @see FcpMessageRuntimeSupport#startProbe(byte, long, FcpProbeType, FcpProbeListener)
 */
public enum FcpProbeType {
  /** Requests or reports probe bandwidth information. */
  BANDWIDTH,
  /** Requests or reports the node build number. */
  BUILD,
  /** Requests or reports the node identifier. */
  IDENTIFIER,
  /** Requests or reports link-length summary information. */
  LINK_LENGTHS,
  /** Requests or reports the node location value. */
  LOCATION,
  /** Requests or reports datastore size information. */
  STORE_SIZE,
  /** Requests or reports 48-hour uptime information. */
  UPTIME_48H,
  /** Requests or reports 7-day uptime information. */
  UPTIME_7D,
  /** Requests or reports bulk reject statistics. */
  REJECT_STATS,
  /** Requests or reports overall bulk output capacity usage. */
  OVERALL_BULK_OUTPUT_CAPACITY_USAGE;

  /**
   * Returns the exact FCP field value used on the wire for this probe type.
   *
   * <p>The result is currently identical to {@link #name()}, but exposing it through a dedicated
   * method makes serialization intent explicit and avoids scattering enum-name assumptions through
   * the message code.
   *
   * @return stable field value string that preserves the existing protocol-visible probe type name.
   */
  @SuppressWarnings("unused")
  public String fieldValue() {
    return name();
  }

  /**
   * Parses an FCP {@code Type} field into the matching adapter-owned probe type.
   *
   * <p>The accepted strings intentionally remain identical to the current enum constant names, so
   * callers preserve existing parsing behavior and error messages. This method forms the adapter's
   * protocol parsing boundary for probe types: inbound field data becomes an adapter-owned enum
   * value here, and only later does the bridge map that value to a runtime probe type.
   *
   * @param fieldValue raw {@code Type} field value supplied by the inbound FCP message and expected
   *     to match one of the adapter-owned enum constant names exactly.
   * @return matching adapter-owned probe type for the supplied wire field value.
   * @throws IllegalArgumentException if {@code fieldValue} does not name a supported probe type and
   *     therefore cannot be represented within the adapter-owned probe vocabulary.
   */
  public static FcpProbeType fromFieldValue(String fieldValue) {
    return valueOf(fieldValue);
  }
}

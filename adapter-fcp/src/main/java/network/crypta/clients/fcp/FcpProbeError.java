package network.crypta.clients.fcp;

/**
 * Adapter-owned enumeration of probe error categories emitted over FCP.
 *
 * <p>This enum defines the stable error vocabulary that the adapter-side probe request and response
 * classes can use without importing the runtime-owned probe error type directly. Its constants are
 * intentionally named to match the long-standing FCP {@code ProbeError} field values, which means
 * the adapter can continue serializing the same wire strings even though the bridge layer now owns
 * the conversion between adapter and runtime types.
 *
 * <p>The enum is protocol-facing rather than implementation-facing. Each value represents a failure
 * category that an FCP client may already understand and react to, such as a timeout, overload, or
 * forwarding failure. Bridge code is responsible for converting live runtime failures into these
 * adapter-owned values before the message layer creates a {@link ProbeError} response.
 *
 * @see FcpProbeListener#onError(FcpProbeError, Byte, boolean)
 * @see ProbeError
 */
public enum FcpProbeError {
  /** The probe disconnected before a terminal result arrived. */
  DISCONNECTED,
  /** The probe was rejected because a local overload guard was active. */
  OVERLOAD,
  /** The probe timed out before a terminal result arrived. */
  TIMEOUT,
  /** The probe reported an unknown error code. */
  UNKNOWN,
  /** The probe type was not recognized by the responding node. */
  UNRECOGNIZED_TYPE,
  /** The probe could not be forwarded to a suitable next hop. */
  CANNOT_FORWARD;

  /**
   * Returns the exact FCP field value used on the wire for this error category.
   *
   * <p>The result is currently identical to {@link #name()}, but this method keeps call sites
   * explicit about their intent: they want the protocol field value, not merely the Java enum name.
   * That leaves room for future adapter-local representation changes while preserving a narrow
   * serialization contract today.
   *
   * @return stable field value string that preserves the existing protocol-visible error token for
   *     this category.
   */
  public String fieldValue() {
    return name();
  }
}

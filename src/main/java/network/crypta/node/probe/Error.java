package network.crypta.node.probe;

/**
 * Enumerates well-known failure conditions that can occur while running a probe in the Crypta
 * network.
 *
 * <p>Each constant represents a distinct class of failure that a probing node or a relaying node
 * can report when a probe cannot be completed successfully. The enum is intentionally coupled with
 * a stable {@linkplain #code numeric code} so that values can be serialized over the network
 * without relying on fragile {@code name()} or ordinal-based encodings. Codes are small and
 * consecutive, starting at zero.
 *
 * <p>Typical usage follows this pattern:
 *
 * <ul>
 *   <li>When emitting an error over the wire, write the {@link #code} value.
 *   <li>When decoding, validate with {@link #isValid(byte)} and then convert using {@link
 *       #valueOf(byte)}. If validation fails, treat the value as unknown for your context.
 * </ul>
 *
 * <p>This type is immutable and thread-safe. It has no mutable state and can be freely shared
 * across threads. The mapping between codes and enum constants is fixed at compile time and does
 * not change at runtime.
 */
public enum Error {
  /**
   * The target node disconnected while the probe awaited a response.
   *
   * <p>This indicates that a network connection or session broke before a definitive outcome could
   * be delivered. The disconnect can originate either from the remote peer voluntarily closing the
   * connection or due to transport-layer failures, timeouts at lower layers, or process shutdowns.
   * Retrying may succeed if the disconnection was transient.
   */
  DISCONNECTED((byte) 0),
  /**
   * The receiving node rejected the probe because a local DoS/overload guard is active.
   *
   * <p>Nodes enforce admission control for probes to protect resources. When limits are exceeded,
   * new probes are refused and this error is emitted. Backing off and retrying after a delay is the
   * recommended strategy; immediate retries are likely to be rejected again while the guard is
   * engaged.
   */
  OVERLOAD((byte) 1),
  /**
   * The probe timed out before a response or terminal failure arrived.
   *
   * <p>Timeouts can result from long network paths, slow or congested links, or nodes that are
   * alive but too busy to respond within the configured time budget. Upstream policies determine
   * the actual timeout thresholds. Callers typically treat this as retryable with exponential
   * backoff.
   */
  TIMEOUT((byte) 2),
  /**
   * A node reported an error code that is not recognized by the local implementation.
   *
   * <p>When received locally, the unrecognized numeric value is preserved alongside this category
   * to aid diagnostics. This generally indicates a version skew between peers or an extension that
   * is not understood. The failure itself is terminal for the current probe; callers should avoid
   * assuming any semantics beyond “not recognized”.
   */
  UNKNOWN((byte) 3),
  /**
   * The remote node understood the request envelope but did not recognize the probe type.
   *
   * <p>This differs from protocol-level errors: for locally started probes an unknown type would be
   * rejected earlier as a protocol error. Over the network it communicates that the peer does not
   * implement the requested probe, which may happen with mixed-version deployments.
   */
  UNRECOGNIZED_TYPE((byte) 4),
  /**
   * The node accepted and understood the request but failed to forward it to the next hop.
   *
   * <p>Forwarding can fail due to routing constraints, peer selection limits, or transient
   * connectivity issues. Implementations usually cap the number of send attempts to prevent
   * excessive retries.
   *
   * @see Probe#MAX_SEND_ATTEMPTS
   */
  CANNOT_FORWARD((byte) 5);

  /**
   * Stable numeric value that represents this constant on the wire.
   *
   * <p>Use this field when serializing an {@code Error} over the network. Do not rely on {@link
   * Enum#name()} or ordinal values; those are unstable across refactorings and re-orderings. Codes
   * are consecutive and begin at zero.
   */
  public final byte code;

  private static final int MAX_CODE = Error.values().length;

  Error(byte code) {
    this.code = code;
  }

  /**
   * Reports whether a numeric code corresponds to a defined {@code Error} value.
   *
   * <p>This helper enables fast validation without exceptions. It checks that the code falls within
   * the inclusive lower bound and exclusive upper bound of known codes. The mapping is stable for a
   * given build. A {@code true} outcome guarantees that {@link #valueOf(byte)} will succeed.
   *
   * <p>Usage example:
   *
   * <pre>{@code
   * if (Error.isValid(code)) {
   *   var e = Error.valueOf(code);
   *   // handle e
   * } else {
   *   // handle unknown code
   * }
   * }</pre>
   *
   * @param code numeric value received from a peer or decoded from storage; values below zero or
   *     beyond the highest assigned code are invalid.
   * @return {@code true} when {@code code} maps to a known constant; {@code false} when it does
   *     not, in which case callers should treat it as unknown.
   */
  static boolean isValid(byte code) {
    // Assumes codes are consecutive, start at zero, and all are valid.
    return code >= 0 && code < MAX_CODE;
  }

  /**
   * Converts a numeric code to its corresponding {@code Error} constant.
   *
   * <p>This method performs a constant-time switch over the supported values and never returns
   * {@code null}. It is idempotent for the same input and does not perform any I/O. Prefer calling
   * {@link #isValid(byte)} first when handling untrusted input to avoid exceptions in hot paths.
   *
   * @param code numeric identifier previously obtained from {@link #code} during serialization or
   *     received from a peer; must be within the set of defined values.
   * @return the non-null {@code Error} constant that matches {@code code}; ownership is shared and
   *     instances are the canonical enum singletons.
   * @throws IllegalArgumentException if there is no constant with the requested {@code code};
   *     callers should treat such cases as an unknown error category.
   */
  static Error valueOf(byte code) throws IllegalArgumentException {
    return switch (code) {
      case 0 -> DISCONNECTED;
      case 1 -> OVERLOAD;
      case 2 -> TIMEOUT;
      case 3 -> UNKNOWN;
      case 4 -> UNRECOGNIZED_TYPE;
      case 5 -> CANNOT_FORWARD;
      default ->
          throw new IllegalArgumentException("There is no ProbeError with code " + code + ".");
    };
  }
}

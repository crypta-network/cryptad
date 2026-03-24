package network.crypta.node.probe;

/**
 * Enumerates the different probe result types exchanged between nodes in the Crypta network.
 *
 * <p>Each constant identifies a specific class of diagnostic or status information that can be
 * requested by a peer and returned by a responding node. The enum associates every type with a
 * compact {@code byte} {@linkplain #code on-the-wire code} that is stable for serialization and
 * deserialization. This allows efficient transmission while keeping the higher-level semantics
 * explicit and type-safe in code.
 *
 * <p>Typical usage is to read a raw {@code byte} value from an inbound message, verify it with
 * {@link #isValid(byte)}, and then obtain the corresponding {@link #valueOf(byte)} to branch on the
 * enum constant. When emitting messages, use the {@link #code} of a constant instead of its ordinal
 * value; the mapping is explicit and not tied to declaration order. Values outside the declared
 * range are considered invalid and must be rejected by callers.
 *
 * <ul>
 *   <li>Mapping is stable: the {@link #code} is assigned explicitly and independent of {@code
 *       ordinal()}.
 *   <li>{@link #valueOf(byte)} throws {@link IllegalArgumentException} for unknown codes.
 *   <li>{@link #isValid(byte)} provides a fast pre-check without using exceptions for control flow.
 * </ul>
 */
public enum Type {
  /**
   * Requests or reports information about a node's bandwidth, such as capacity or recent
   * utilization, subject to the probe protocol details.
   */
  BANDWIDTH((byte) 0),
  /** Reports the build identifier or version information for the running node software. */
  BUILD((byte) 1),
  /**
   * Exchanges a stable node identifier value as defined by the protocol, enabling peers to
   * correlate responses with a specific node across requests.
   */
  IDENTIFIER((byte) 2),
  /** Provides summary statistics describing link length distributions in the network topology. */
  LINK_LENGTHS((byte) 3),
  /** Reports coarse location or placement information used by the routing layer. */
  LOCATION((byte) 4),
  /** Conveys the size or capacity of local persistent stores managed by the node. */
  STORE_SIZE((byte) 5),
  /** Returns a node uptime measurement aggregated over a recent 48-hour window. */
  UPTIME_48H((byte) 6),
  /** Returns a node uptime measurement aggregated over a recent 7-day window. */
  UPTIME_7D((byte) 7),
  /** Reports request rejection statistics to aid diagnosis of overload or policy throttling. */
  REJECT_STATS((byte) 8),
  /**
   * Reports aggregated bulk output capacity usage, suitable for understanding sustained egress load
   * relative to configured limits.
   */
  OVERALL_BULK_OUTPUT_CAPACITY_USAGE((byte) 9);

  /**
   * Compact, stable {@code byte} value used on the wire to represent this probe type.
   *
   * <p>The value is explicitly assigned per constant and is independent of {@link #ordinal()}. It
   * is immutable and designed for serialization/deserialization; callers should not infer ordering
   * or density beyond the fact that valid codes occupy the range {@code 0..(values().length-1)}.
   */
  public final byte code;

  private static final int MAX_CODE = Type.values().length;

  Type(byte code) {
    this.code = code;
  }

  /**
   * Checks whether {@link #valueOf(byte)} will succeed for the given code without throwing.
   *
   * <p>This helper exists to avoid using exceptions for control flow when parsing untrusted input.
   * A return value of {@code true} indicates the code maps to one of the declared enum constants at
   * the time of the call. The check is constant-time with respect to the number of enum constants.
   *
   * @param code the raw on-the-wire value to validate; values below zero are always invalid.
   * @return {@code true} when the code corresponds to a declared constant; {@code false} otherwise.
   */
  static boolean isValid(byte code) {
    return code >= 0 && code < MAX_CODE;
  }

  /**
   * Determines the enum constant that corresponds to the supplied on-the-wire code.
   *
   * <p>This method performs a direct mapping from the compact {@code byte} representation to the
   * strongly typed {@code Type}. It is idempotent and side effect free. Callers should prefer
   * {@link #isValid(byte)} to guard inputs when handling data from untrusted peers.
   *
   * @param code the compact code to resolve; must match one of the declared constants.
   * @return the {@code Type} constant corresponding to {@code code}; never {@code null}.
   * @throws IllegalArgumentException if {@code code} does not correspond to any declared constant.
   */
  static Type valueOf(byte code) throws IllegalArgumentException {
    return switch (code) {
      case 0 -> BANDWIDTH;
      case 1 -> BUILD;
      case 2 -> IDENTIFIER;
      case 3 -> LINK_LENGTHS;
      case 4 -> LOCATION;
      case 5 -> STORE_SIZE;
      case 6 -> UPTIME_48H;
      case 7 -> UPTIME_7D;
      case 8 -> REJECT_STATS;
      case 9 -> OVERALL_BULK_OUTPUT_CAPACITY_USAGE;
      default ->
          throw new IllegalArgumentException("There is no ProbeType with code " + code + ".");
    };
  }
}

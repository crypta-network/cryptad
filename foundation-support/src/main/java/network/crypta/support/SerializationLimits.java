package network.crypta.support;

/**
 * Centralized size limits for generic support-side serialization helpers.
 *
 * <p>This class gives `:foundation-support` a small, stable home for limits that belong to
 * low-level value types and deserialization helpers rather than to a specific runtime subsystem or
 * packet-format implementation. The goal is to let classes such as {@code Buffer} and {@code
 * BitArray} enforce the same bounds without importing root-owned networking code.
 *
 * <p>Keep this class intentionally narrow. It is for reusable serialization bounds that apply to
 * support-owned helpers across the tree, not for broader protocol constants, transport tuning, or
 * runtime configuration. If a limit is specific to one wire format or one daemon subsystem, it
 * should stay with that owner instead of being added here.
 */
public final class SerializationLimits {
  /**
   * Maximum permitted length, in bytes, for generic array-backed payloads accepted by support-side
   * deserialization helpers.
   *
   * <p>Use this bound when reading variable-length byte content whose validation belongs to generic
   * support code rather than to a higher-level wire-format implementation.
   */
  public static final int MAX_ARRAY_LENGTH = 4092;

  /**
   * Maximum permitted logical size, in bits, for a {@code BitArray} accepted during
   * deserialization.
   *
   * <p>This limit prevents oversized bit-array allocations in generic support code while keeping
   * the shared bound explicit and easy to reuse from compatibility aliases.
   */
  public static final int MAX_BITARRAY_SIZE = 2048 * 8;

  private SerializationLimits() {}
}

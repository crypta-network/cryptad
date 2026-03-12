package network.crypta.node;

import java.util.Arrays;
import org.jetbrains.annotations.NotNull;

/**
 * Encapsulates a fragment payload buffer together with its optional origin wrapper.
 *
 * <p>This record bundles the raw fragment bytes and a reference back to the {@link MessageWrapper}
 * that produced them, if any. It exists to keep {@link MessageFragment} construction succinct while
 * still preserving the protocol metadata and payload as separate concepts. The record does not
 * validate sizes or copy the buffer, so callers must honor the owning message's invariants and
 * avoid mutating the array after construction if immutability is expected. Instances are
 * lightweight and may be shared across threads as long as the underlying {@code fragmentData}
 * remains stable. Equality and hashing are defined in terms of the buffer contents and wrapper
 * identity, which preserves protocol correctness without forcing wrapper equality semantics.
 *
 * <ul>
 *   <li>Stores the payload bytes used for sizing and transmission.
 *   <li>Tracks the sender-side wrapper when available, otherwise {@code null}.
 *   <li>Leaves lifecycle and threading guarantees to the caller and referenced wrapper.
 * </ul>
 *
 * @see MessageFragment
 * @see MessageWrapper
 */
@SuppressWarnings("java:S6206")
final class MessageFragmentPayload {
  private final byte[] fragmentData;
  private final MessageWrapper wrapper;

  /**
   * @param fragmentData payload bytes of this fragment; used for size and transmission
   * @param wrapper originating wrapper when sending; {@code null} when created by a receiver
   */
  MessageFragmentPayload(byte[] fragmentData, MessageWrapper wrapper) {
    this.fragmentData = fragmentData;
    this.wrapper = wrapper;
  }

  byte[] fragmentData() {
    return fragmentData;
  }

  MessageWrapper wrapper() {
    return wrapper;
  }

  /**
   * Compares this payload to another object using buffer contents and wrapper identity.
   *
   * <p>The comparison is content-based for the byte array, so two payloads with identical {@code
   * fragmentData} values are considered equal even if the arrays are distinct instances. The
   * wrapper comparison uses reference equality to avoid invoking any wrapper-level semantics. This
   * makes the method suitable for cache keys or test assertions where the payload bytes are the
   * primary concern and wrapper ownership must remain stable.
   *
   * @param obj object to compare against; may be {@code null} or another payload instance
   * @return {@code true} when the other object is a payload with matching bytes and wrapper
   *     identity
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof MessageFragmentPayload other)) {
      return false;
    }
    return Arrays.equals(fragmentData, other.fragmentData) && wrapper == other.wrapper;
  }

  /**
   * Computes a hash code based on payload bytes and wrapper identity.
   *
   * <p>The hash uses {@link Arrays#hashCode(byte[])} for the buffer contents and combines it with
   * the wrapper's identity hash. This mirrors {@link #equals(Object)} so that two payloads that are
   * equal in terms of bytes and wrapper reference produce the same hash. The computation is
   * deterministic and does not allocate beyond the array walk.
   *
   * @return a hash suitable for hash-based collections that track payload equality
   */
  @Override
  public int hashCode() {
    int result = Arrays.hashCode(fragmentData);
    result = 31 * result + System.identityHashCode(wrapper);
    return result;
  }

  /**
   * Formats a readable summary containing the payload bytes and wrapper reference.
   *
   * <p>The output embeds {@link Arrays#toString(byte[])} for the payload and the wrapper's {@code
   * toString()} representation (or {@code null} when no wrapper exists). This method is intended
   * for diagnostics and tests; it does not redact content and therefore should not be used for
   * logging sensitive payloads. The returned string is non-null and can be safely used in
   * assertions or debug output.
   *
   * @return a non-null string containing the byte contents and wrapper reference
   */
  @Override
  public @NotNull String toString() {
    return "MessageFragmentPayload[fragmentData="
        + Arrays.toString(fragmentData)
        + ", wrapper="
        + wrapper
        + ']';
  }
}

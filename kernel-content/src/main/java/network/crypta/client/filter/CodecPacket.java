package network.crypta.client.filter;

import java.util.Arrays;

/**
 * Light-weight container for a codec packet's raw payload bytes.
 *
 * <p>This type is a light-weight container used by the client-side filtering and codec layer to
 * represent a single packet as a contiguous byte array. It does not perform decoding or validation;
 * it simply carries the payload between stages that expect a concrete {@code byte[]}
 * representation. Typical usage constructs an instance with a byte array, passes it across
 * boundaries where parsing or transformation occurs, and finally extracts the array via {@link
 * #toArray()} for downstream I/O or protocol handling.
 *
 * <p>The instance stores the provided array reference without copying. As a consequence, the
 * content of the array defines both equality and the hash code. If the array content is modified
 * after construction, the results of {@link #equals(Object)} and {@link #hashCode()} may change.
 * Callers should therefore avoid mutating the payload when instances are used as map keys or are
 * shared across components that assume stable identity.
 *
 * <ul>
 *   <li>Equality is content-based via {@link Arrays#equals(byte[], byte[])}, not by reference.
 *   <li>Hash code follows {@link Arrays#hashCode(byte[])}, enabling use in hashed collections.
 *   <li>The payload array may be {@code null}; methods document behavior for this case.
 * </ul>
 *
 * @see Arrays#equals(byte[], byte[])
 * @see Arrays#hashCode(byte[])
 */
public class CodecPacket {
  /**
   * Raw packet payload bytes held by this container.
   *
   * <p>The reference is stored as provided by the creator and may be {@code null}. The contents of
   * this array define both equality and hashing for the enclosing instance. Because arrays are
   * mutable, changes to the contents after construction will be reflected in later equality and
   * hash-code computations. Prefer treating the data as effectively immutable once published.
   */
  protected byte[] payload;

  CodecPacket(byte[] payload) {
    this.payload = payload;
  }

  /**
   * Returns the underlying payload array without copying.
   *
   * <p>The returned reference is the same array that was supplied at construction time. No deep or
   * defensive copy is created, so subsequent modifications to its contents will be visible to any
   * holders of this instance and may affect the results of {@link #equals(Object)} and {@link
   * #hashCode()} for collections that already contain this object.
   *
   * <pre>{@code
   * // Example: extracting bytes for downstream processing
   * CodecPacket packet = new CodecPacket(bytes);
   * byte[] raw = packet.toArray();
   * // Pass raw to an encoder/decoder as needed
   * }</pre>
   *
   * @return the same {@code byte[]} reference supplied to the constructor; may be {@code null} when
   *     the payload is intentionally absent or unknown.
   */
  public byte[] toArray() {
    return payload;
  }

  /**
   * Computes a hash code derived from the payload contents.
   *
   * <p>The calculation delegates to {@link Arrays#hashCode(byte[])}. If the payload is {@code
   * null}, the returned value follows {@code Arrays.hashCode(null)} semantics (zero). When the
   * array content changes after construction, the hash code changes correspondingly, which can
   * disrupt hashed collections; avoid mutating payloads used as keys.
   *
   * @return an integer hash code consistent with {@link #equals(Object)} for the current payload
   *     contents; returns {@code 0} when the payload is {@code null}.
   */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + Arrays.hashCode(payload);
    return result;
  }

  /**
   * Compares this packet to another for content equality.
   *
   * <p>Two instances are considered equal when their payload arrays are equal according to {@link
   * Arrays#equals(byte[], byte[])}. This comparison is null-safe; a {@code null} payload is only
   * equal to another {@code null} payload. Reference identity is short-circuited for efficiency
   * when the same object is compared to itself.
   *
   * @param obj another object to compare against; equality is defined only for other {@code
   *     CodecPacket} instances based on the byte array contents and nullness.
   * @return {@code true} when {@code obj} is a {@code CodecPacket} whose payload equals this
   *     instance's payload by content; {@code false} otherwise.
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (!(obj instanceof CodecPacket other)) return false;
    return Arrays.equals(payload, other.payload);
  }
}

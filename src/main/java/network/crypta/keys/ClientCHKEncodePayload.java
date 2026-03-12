package network.crypta.keys;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * Bundles the payload inputs required for client-side CHK encoding.
 *
 * <p>This value object captures the data buffer, the original unpadded length, a caller-supplied
 * SHA-256 {@link MessageDigest}, and the encryption key bytes used during CHK block creation. It is
 * typically assembled after compression/padding and before encryption so that encode paths can pass
 * a single object rather than multiple parallel arguments. Instances are shallow and immutable with
 * respect to the field references, but the referenced arrays and digest remain caller-owned and
 * mutable.
 *
 * <p>The payload does not validate sizes or algorithm choices; it is a transport container whose
 * consumers enforce preconditions. Because the arrays are not copied, callers should treat them as
 * read-only for the duration of encoding to avoid inconsistent results in equality, hash codes, or
 * downstream cryptographic outputs. The instance has no lifecycle beyond construction and may be
 * safely reused by sequential operations when the referenced objects are stable.
 *
 * <ul>
 *   <li>Collects the padded payload bytes and original length for header encoding.
 *   <li>Retains the caller-managed digest and encryption key references.
 *   <li>Provides value-style equality that accounts for array contents.
 * </ul>
 *
 * @see ClientCHKEncodeParams
 * @see ClientCHKEncodeAlgorithms
 */
@SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
public final class ClientCHKEncodePayload {
  private final byte[] data;
  private final int dataLength;
  private final MessageDigest md256;
  private final byte[] encKey;

  /**
   * Creates a payload bundle for CHK block encoding.
   *
   * <p>This constructor stores the provided references verbatim and performs no validation or
   * defensive copying. The {@code data} buffer is expected to represent a padded CHK payload (often
   * {@link CHKBlock#DATA_LENGTH} bytes), while {@code dataLength} records the original unpadded
   * size used in header computations. The digest and key are retained for downstream use, and
   * callers remain responsible for their lifecycle and mutability.
   *
   * @param data padded payload buffer reference; treated as read-only by callers during encoding
   * @param dataLength original unpadded data length in bytes; typically within payload size bounds
   * @param md256 reusable SHA-256 digest instance; may be shared and is not cloned by this object
   * @param encKey encryption key bytes for the block; stored as provided without copying
   */
  public ClientCHKEncodePayload(byte[] data, int dataLength, MessageDigest md256, byte[] encKey) {
    this.data = data;
    this.dataLength = dataLength;
    this.md256 = md256;
    this.encKey = encKey;
  }

  /**
   * Returns the padded payload buffer reference used for encoding.
   *
   * <p>The returned array is the exact reference supplied at construction time and is not copied.
   * Callers should treat it as immutable for the duration of encoding to avoid non-deterministic
   * cryptographic output or inconsistent equality comparisons. The buffer is expected to contain
   * any padding already applied, with the original length accessible via {@link #dataLength()}.
   *
   * @return the padded payload byte array reference, not copied or normalized
   */
  public byte[] data() {
    return data;
  }

  /**
   * Returns the original unpadded data length in bytes.
   *
   * <p>This value records how many bytes in the padded payload are meaningful prior to padding and
   * is typically encoded into the CHK header. The value is stored verbatim without range checks, so
   * callers should ensure it is consistent with the associated buffer size and encoding rules.
   *
   * @return the original unpadded length in bytes, as supplied at construction time
   */
  public int dataLength() {
    return dataLength;
  }

  /**
   * Returns the SHA-256 {@link MessageDigest} reference associated with this payload.
   *
   * <p>The digest instance is stored as provided and is neither cloned nor reset. Callers are
   * responsible for any synchronization if the digest is reused concurrently and for resetting its
   * state if they share it across operations. This method returns the same reference each time.
   *
   * @return the caller-managed digest instance used for SHA-256 operations
   */
  public MessageDigest md256() {
    return md256;
  }

  /**
   * Returns the encryption key bytes used for the block.
   *
   * <p>The returned array is the original reference supplied at construction time. It is not copied
   * or protected from modification, so callers should treat it as immutable for the duration of any
   * encoding that relies on deterministic key material. The interpretation of the bytes depends on
   * the selected crypto algorithm in the surrounding encoding parameters.
   *
   * @return the encryption key byte array reference, not copied or sanitized
   */
  public byte[] encKey() {
    return encKey;
  }

  /**
   * Compares this payload with another object for value equality.
   *
   * <p>Two payloads are equal when their {@code dataLength} values match, the {@code data} and
   * {@code encKey} arrays contain identical contents, and the digest references are equal according
   * to {@link Objects#equals(Object, Object)}. This comparison is deterministic only if the
   * underlying arrays and digest reference are not mutated during comparison.
   *
   * @param obj object to compare against; may be {@code null}
   * @return {@code true} when all stored fields and array contents are equal
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (!(obj instanceof ClientCHKEncodePayload other)) return false;
    return dataLength == other.dataLength
        && Arrays.equals(data, other.data)
        && Objects.equals(md256, other.md256)
        && Arrays.equals(encKey, other.encKey);
  }

  /**
   * Computes a hash code consistent with {@link #equals(Object)}.
   *
   * <p>The hash mixes the digest reference, the scalar length, and the array contents. Because the
   * arrays are mutable and not copied, the hash code is only stable when the referenced arrays and
   * digest remain unchanged. Avoid using instances as long-lived keys in hash-based collections
   * when the underlying buffers may be mutated.
   *
   * @return a hash code derived from the digest reference, length, and array contents
   */
  @Override
  public int hashCode() {
    int result = Objects.hash(md256, dataLength);
    result = 31 * result + Arrays.hashCode(data);
    result = 31 * result + Arrays.hashCode(encKey);
    return result;
  }

  /**
   * Returns a diagnostic string describing the payload contents.
   *
   * <p>The representation includes the full array contents via {@link Arrays#toString(byte[])} and
   * the digest reference. This can be useful for debugging but may expose sensitive material or be
   * expensive for large buffers. Callers should avoid logging the result in production contexts
   * where key material or payload bytes must remain confidential.
   *
   * @return a non-null string containing all stored fields and array contents
   */
  @Override
  public @NotNull String toString() {
    return "ClientCHKEncodePayload[data="
        + Arrays.toString(data)
        + ", dataLength="
        + dataLength
        + ", md256="
        + md256
        + ", encKey="
        + Arrays.toString(encKey)
        + "]";
  }
}

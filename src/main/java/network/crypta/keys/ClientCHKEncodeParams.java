package network.crypta.keys;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * Bundles the parameters needed to build a client-side CHK block.
 *
 * <p>This type is a small, immutable carrier for the inputs that a client-side encoder needs when
 * producing a CHK block and its associated key material. It gathers the padded data buffer, the
 * original unpadded length, crypto identifiers, and reusable cryptographic primitives into a single
 * object so that call sites can pass one parameter instead of a long argument list. A typical usage
 * is to assemble these parameters during request preparation and then hand the instance to the
 * encoder that emits the block.
 *
 * <p>The instance does not copy the provided arrays and therefore reflects the caller-provided
 * buffers directly. Callers should treat the arrays as read-only after construction. There is no
 * internal lifecycle beyond construction, and equality compares the complete parameter set,
 * including array contents. This class is not thread-safe if the arrays or the {@link
 * MessageDigest} are mutated concurrently by the caller.
 *
 * <ul>
 *   <li>Collects data buffers, lengths, and algorithm identifiers for CHK encoding.
 *   <li>Captures whether the resulting key represents metadata or content.
 *   <li>Preserves the caller-provided digest instance for reuse.
 * </ul>
 *
 * @see CHKBlock
 */
public final class ClientCHKEncodeParams {
  private final ClientCHKEncodePayload payload;
  private final ClientCHKEncodeAlgorithms algorithms;

  /**
   * Creates a parameter bundle for CHK block encoding.
   *
   * @param payload payload buffers, lengths, and digest to use for encoding
   * @param algorithms metadata and algorithm identifiers to embed in the block header
   */
  public ClientCHKEncodeParams(
      ClientCHKEncodePayload payload, ClientCHKEncodeAlgorithms algorithms) {
    this.payload = payload;
    this.algorithms = algorithms;
  }

  /**
   * Returns the padded data buffer used for block encoding.
   *
   * <p>The returned array is the exact reference provided at construction time and is not copied.
   * Callers should treat it as read-only to avoid surprising changes to equality or to any
   * downstream encoding behavior. The buffer is expected to be sized for a full CHK payload, but
   * the original length is available from {@link #dataLength()}.
   *
   * @return the padded payload buffer reference, not copied or normalized
   */
  public byte[] data() {
    return payload.data();
  }

  /**
   * Returns the original unpadded data length in bytes.
   *
   * <p>This length indicates how many bytes in the padded payload buffer are meaningful prior to
   * padding and is typically encoded into the block header. It does not imply any validation and
   * may be equal to the full payload size when no padding is required.
   *
   * @return the original unpadded data length in bytes
   */
  public int dataLength() {
    return payload.dataLength();
  }

  /**
   * Returns the reusable SHA-256 digest instance associated with this parameter set.
   *
   * <p>The digest reference is stored as provided. If the caller reuses or mutates the digest
   * concurrently, this instance reflects those changes and is not thread-safe by itself. This
   * accessor performs no cloning or resetting.
   *
   * @return the {@link MessageDigest} instance used for SHA-256 operations
   */
  public MessageDigest md256() {
    return payload.md256();
  }

  /**
   * Returns the encryption key bytes used for block encoding.
   *
   * <p>The returned array is the original reference supplied at construction time. It is not copied
   * or protected from modification, so callers should treat it as immutable after construction to
   * avoid inconsistent behavior across encoding and equality checks.
   *
   * @return the encryption key byte array reference, not copied
   */
  public byte[] encKey() {
    return payload.encKey();
  }

  /**
   * Indicates whether the resulting key should be marked as metadata.
   *
   * <p>This flag is carried into the key encoding to distinguish metadata blocks from content
   * blocks. The value is stored verbatim and does not affect any other fields in this object.
   *
   * @return {@code true} when the key represents metadata, {@code false} for content
   */
  public boolean asMetadata() {
    return algorithms.asMetadata();
  }

  /**
   * Returns the compression algorithm identifier stored in the key.
   *
   * <p>The identifier is an implementation-defined short value used by the CHK format. This object
   * does not validate the value; it simply stores and returns it for the encoder.
   *
   * @return the compression algorithm identifier as a short
   */
  public short compressionAlgorithm() {
    return algorithms.compressionAlgorithm();
  }

  /**
   * Returns the crypto algorithm identifier used for block encryption.
   *
   * <p>The value is stored verbatim and is intended to be encoded in the block header. This class
   * does not interpret or validate the identifier.
   *
   * @return the crypto algorithm identifier as a byte
   */
  public byte cryptoAlgorithm() {
    return algorithms.cryptoAlgorithm();
  }

  /**
   * Returns the block hash algorithm identifier recorded in the header.
   *
   * <p>This identifier specifies which hash algorithm should be associated with the block. The
   * value is stored without validation or normalization.
   *
   * @return the block hash algorithm identifier as an integer
   */
  public int blockHashAlgorithm() {
    return algorithms.blockHashAlgorithm();
  }

  /**
   * Compares this instance with another object for value equality.
   *
   * <p>Two instances are equal when all scalar fields match, and both the data and encryption key
   * arrays contain identical contents. Reference equality compares the digest instance via {@link
   * Objects#equals(Object, Object)}. This method is symmetric and deterministic as long as the
   * underlying arrays and digest reference are not mutated during comparison.
   *
   * @param obj the object to compare against, may be {@code null}
   * @return {@code true} when all fields and array contents match, otherwise {@code false}
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (!(obj instanceof ClientCHKEncodeParams other)) return false;
    return dataLength() == other.dataLength()
        && asMetadata() == other.asMetadata()
        && compressionAlgorithm() == other.compressionAlgorithm()
        && cryptoAlgorithm() == other.cryptoAlgorithm()
        && blockHashAlgorithm() == other.blockHashAlgorithm()
        && Arrays.equals(data(), other.data())
        && Objects.equals(md256(), other.md256())
        && Arrays.equals(encKey(), other.encKey());
  }

  /**
   * Computes a hash code based on all stored parameters.
   *
   * <p>The hash combines scalar fields and array contents so it is consistent with {@link
   * #equals(Object)}. If the arrays are mutated after construction, the hash code may change and
   * the instance should not be used as a stable key in hash-based collections.
   *
   * @return a hash code derived from all stored fields and array contents
   */
  @Override
  public int hashCode() {
    int result =
        Objects.hash(
            md256(),
            dataLength(),
            asMetadata(),
            compressionAlgorithm(),
            cryptoAlgorithm(),
            blockHashAlgorithm());
    result = 31 * result + Arrays.hashCode(data());
    result = 31 * result + Arrays.hashCode(encKey());
    return result;
  }

  /**
   * Returns a string representation of this parameter set.
   *
   * <p>The string includes the scalar values and a full {@link Arrays#toString(byte[])} rendering
   * of the data and encryption key arrays. This is intended for diagnostics and should not be used
   * for logging sensitive material in production contexts.
   *
   * @return a human-readable representation of this parameter set
   */
  @Override
  public @NotNull String toString() {
    return "ClientCHKEncodeParams["
        + "data="
        + Arrays.toString(data())
        + ", dataLength="
        + dataLength()
        + ", md256="
        + md256()
        + ", encKey="
        + Arrays.toString(encKey())
        + ", asMetadata="
        + asMetadata()
        + ", compressionAlgorithm="
        + compressionAlgorithm()
        + ", cryptoAlgorithm="
        + cryptoAlgorithm()
        + ", blockHashAlgorithm="
        + blockHashAlgorithm()
        + "]";
  }
}

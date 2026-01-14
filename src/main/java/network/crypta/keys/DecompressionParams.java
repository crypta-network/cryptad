package network.crypta.keys;

import java.util.Arrays;
import java.util.Objects;
import network.crypta.support.api.BucketFactory;
import org.jetbrains.annotations.NotNull;

/**
 * Bundles the inputs required to decode and optionally decompress block data.
 *
 * <p>This record acts as a compact carrier for the flags, buffers, and limits that shape a single
 * decompression attempt. It is typically assembled close to the call site that already has the raw
 * bytes, then passed into {@link Key#decompress(DecompressionParams)} to keep method signatures
 * concise and consistent across call paths. The record is shallowly immutable, but it holds a
 * mutable {@code byte[]} reference; callers should treat the array as read-only for the lifetime of
 * the decode operation to avoid surprising results.
 *
 * <p>Instances are inexpensive to allocate and intended to be short-lived. The values capture size
 * constraints, codec identifiers, and header sizing behavior so that the decompressor can validate
 * bounds consistently across different key types. The record itself performs no validation; all
 * preconditions are enforced by the decode method that consumes it.
 *
 * <ul>
 *   <li>Encapsulates compression flags, limits, and byte buffers for a single decoding.
 *   <li>Documents the expected header length policy through {@code shortLength}.
 *   <li>Centralizes bounds and codec metadata for consistent error handling.
 * </ul>
 *
 * @param isCompressed whether the payload uses compression for this decode operation
 * @param input raw input bytes to read from; the array is not copied and should be treated as
 *     immutable while decoding
 * @param inputLength number of bytes from {@code input} that are valid for this decoding, in bytes
 * @param bf bucket factory used to allocate the decoded output bucket; may be reused by callers
 * @param maxLength upper bound on the decompressed output size, in bytes; the decoder rejects
 *     negative values
 * @param compressionAlgorithm compression codec identifier expected by the decoder; negative values
 *     mean no compression
 * @param shortLength whether the precompressed-length header uses 2 bytes instead of 4 for this
 *     payload
 * @see Key#decompress(DecompressionParams)
 */
public record DecompressionParams(
    boolean isCompressed,
    byte[] input,
    int inputLength,
    BucketFactory bf,
    long maxLength,
    short compressionAlgorithm,
    boolean shortLength) {
  /**
   * Compares this parameter bundle with another for structural equality.
   *
   * <p>The comparison treats {@code input} as a content-bearing buffer and therefore uses {@link
   * Arrays#equals(byte[], byte[])} rather than reference equality. All scalar fields are compared
   * directly, while {@code bf} is compared using {@link Objects#equals(Object, Object)} so that a
   * {@code null} factory is handled consistently. This method performs no validation; it simply
   * reflects the values stored in the record components at the time of comparison.
   *
   * @param obj the object to compare against; may be {@code null} or of another type
   * @return {@code true} when all fields, including the byte contents, match exactly
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (!(obj
        instanceof
        DecompressionParams(
            boolean otherIsCompressed,
            byte[] otherInput,
            int otherInputLength,
            BucketFactory otherBf,
            long otherMaxLength,
            short otherCompressionAlgorithm,
            boolean otherShortLength))) return false;
    return isCompressed == otherIsCompressed
        && inputLength == otherInputLength
        && maxLength == otherMaxLength
        && compressionAlgorithm == otherCompressionAlgorithm
        && shortLength == otherShortLength
        && Objects.equals(bf, otherBf)
        && Arrays.equals(input, otherInput);
  }

  /**
   * Computes a hash code consistent with {@link #equals(Object)}.
   *
   * <p>The hash incorporates the content of {@code input} via {@link Arrays#hashCode(byte[])} and
   * then mixes in the remaining scalar fields. The bucket factory contributes its own hash code
   * when present; a {@code null} factory contributes {@code 0}. This makes the hash stable for
   * identical parameter sets while remaining inexpensive for short-lived comparisons in
   * collections.
   *
   * @return a hash code derived from the buffer contents and all other fields
   */
  @Override
  public int hashCode() {
    int result = Arrays.hashCode(input);
    result = 31 * result + Boolean.hashCode(isCompressed);
    result = 31 * result + Integer.hashCode(inputLength);
    result = 31 * result + (bf == null ? 0 : bf.hashCode());
    result = 31 * result + Long.hashCode(maxLength);
    result = 31 * result + Short.hashCode(compressionAlgorithm);
    result = 31 * result + Boolean.hashCode(shortLength);
    return result;
  }

  /**
   * Returns a diagnostic string describing this parameter bundle.
   *
   * <p>The output lists every component, including the full byte content of {@code input} via
   * {@link Arrays#toString(byte[])}. Because the byte array is rendered eagerly, callers should
   * avoid invoking this method on very large buffers in hot paths. The returned value is never
   * {@code null} and is suitable for logs or debugging output when a full buffer dump is
   * acceptable.
   *
   * @return a non-null string containing all fields and the input byte contents
   */
  @Override
  public @NotNull String toString() {
    return "DecompressionParams[isCompressed="
        + isCompressed
        + ", input="
        + Arrays.toString(input)
        + ", inputLength="
        + inputLength
        + ", bf="
        + bf
        + ", maxLength="
        + maxLength
        + ", compressionAlgorithm="
        + compressionAlgorithm
        + ", shortLength="
        + shortLength
        + "]";
  }
}

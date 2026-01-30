package network.crypta.client;

import java.util.Arrays;
import java.util.Objects;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.crypt.HashResult;
import org.jetbrains.annotations.NotNull;

/**
 * Carries top-layer sizing, compatibility, and hash details for {@link Metadata}.
 *
 * <p>This record groups the fields that describe how the outermost metadata layer should be
 * interpreted: the original and compressed byte lengths, the number of required and total blocks,
 * the top-layer compression preference, and any hashes that apply to the final data or just the
 * current layer. It is typically constructed alongside {@link MetadataRedirectTarget} or {@link
 * SplitfilePayload} and then supplied to {@link Metadata} constructors that need to serialize or
 * validate top-layer information. The record preserves inputs exactly as provided, allowing the
 * metadata encoder to remain focused on formatting and validation rather than value synthesis.
 *
 * <p>Instances are immutable, but array components are not copied. Callers should treat the
 * referenced arrays as stable for the duration of metadata construction and avoid mutating them
 * after passing this record to any encoder. All numeric values represent byte counts or block
 * counts and are expected to be non-negative; consistency between sizes and block totals is the
 * caller's responsibility.
 *
 * <ul>
 *   <li>Captures original and compressed lengths in bytes for the top layer.
 *   <li>Stores block-count signals that inform progress reporting and recovery.
 *   <li>Separates final-data hashes from optional layer-local hashes.
 * </ul>
 *
 * @param origDataLength original uncompressed byte length for the top layer; zero when unknown.
 * @param origCompressedDataLength original compressed byte length; zero when unknown or unused.
 * @param requiredBlocks minimum blocks required to reconstruct the final data; non-negative.
 * @param totalBlocks total blocks inserted for the final data; non-negative and >= required.
 * @param topDontCompress whether top-layer compression was intentionally disabled by the caller.
 * @param topCompatibilityMode declared compatibility mode for the insert; never {@code null}.
 * @param hashes hashes of the final/original data; may be {@code null} or empty.
 * @param hashThisLayerOnly hash of only this metadata layer; may be {@code null}.
 * @see Metadata
 * @see MetadataRedirectTarget
 * @see SplitfilePayload
 */
@SuppressWarnings("ArrayRecordComponent")
public record MetadataTopLayerInfo(
    long origDataLength,
    long origCompressedDataLength,
    int requiredBlocks,
    int totalBlocks,
    boolean topDontCompress,
    CompatibilityMode topCompatibilityMode,
    HashResult[] hashes,
    byte[] hashThisLayerOnly) {

  /**
   * Returns an instance representing the absence of any top-layer sizing or hash data.
   *
   * <p>The returned instance uses zero lengths and block counts, {@link
   * CompatibilityMode#COMPAT_UNKNOWN} for compatibility, and {@code null} for both hash arrays. It
   * is intended for call sites that do not have top-layer information or that want to indicate that
   * no top-layer fields should be serialized. The returned instance is immutable and safe to share
   * across threads as long as callers treat it as a constant.
   *
   * @return a canonical "empty" top-layer info instance with no sizes or hashes.
   */
  public static MetadataTopLayerInfo none() {
    return new MetadataTopLayerInfo(
        0, 0, 0, 0, false, CompatibilityMode.COMPAT_UNKNOWN, null, null);
  }

  /**
   * Compares this instance to another by value, including array contents.
   *
   * <p>The comparison checks all scalar components and uses {@link Arrays#equals(Object[],
   * Object[]) Arrays.equals} for array components, treating {@code null} arrays as equal only to
   * {@code null} arrays. This method performs a shallow comparison of array elements and does not
   * clone or normalize inputs. It is appropriate when the arrays supplied to the record are stable
   * for the duration of comparison and should not be used if callers mutate arrays after
   * construction.
   *
   * @param o object to compare against; may be {@code null} or of another type.
   * @return {@code true} when all components, including array contents, are equal.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o
        instanceof
        MetadataTopLayerInfo(
            long otherOrigDataLength,
            long otherOrigCompressedDataLength,
            int otherRequiredBlocks,
            int otherTotalBlocks,
            boolean otherTopDontCompress,
            CompatibilityMode otherTopCompatibilityMode,
            HashResult[] otherHashes,
            byte[] otherHashThisLayerOnly))) {
      return false;
    }
    return origDataLength == otherOrigDataLength
        && origCompressedDataLength == otherOrigCompressedDataLength
        && requiredBlocks == otherRequiredBlocks
        && totalBlocks == otherTotalBlocks
        && topDontCompress == otherTopDontCompress
        && topCompatibilityMode == otherTopCompatibilityMode
        && Arrays.equals(hashes, otherHashes)
        && Arrays.equals(hashThisLayerOnly, otherHashThisLayerOnly);
  }

  /**
   * Computes a hash code that incorporates array contents.
   *
   * <p>The hash combines scalar components with {@link Arrays#hashCode(Object[])} for array fields,
   * producing a shallow hash that depends on the current contents of the arrays. This makes the
   * hash code suitable for use as a map key only when callers do not mutate the arrays after
   * construction. The method performs no copying and assumes the record's components are stable.
   *
   * @return a hash code derived from all components, including array contents.
   */
  @Override
  public int hashCode() {
    int result =
        Objects.hash(
            origDataLength,
            origCompressedDataLength,
            requiredBlocks,
            totalBlocks,
            topDontCompress,
            topCompatibilityMode);
    result = 31 * result + Arrays.hashCode(hashes);
    result = 31 * result + Arrays.hashCode(hashThisLayerOnly);
    return result;
  }

  /**
   * Returns a string representation that includes array contents.
   *
   * <p>The string lists each component in order and uses {@link Arrays#toString(Object[])} for the
   * array fields. It is intended for diagnostics and logging, not for stable serialization or
   * parsing. The output will reflect the current contents of any arrays at the time of the call, so
   * callers should avoid mutating arrays if a stable representation is required.
   *
   * @return a non-null diagnostic string containing all component values and array contents.
   */
  @Override
  public @NotNull String toString() {
    return "MetadataTopLayerInfo["
        + "origDataLength="
        + origDataLength
        + ", origCompressedDataLength="
        + origCompressedDataLength
        + ", requiredBlocks="
        + requiredBlocks
        + ", totalBlocks="
        + totalBlocks
        + ", topDontCompress="
        + topDontCompress
        + ", topCompatibilityMode="
        + topCompatibilityMode
        + ", hashes="
        + Arrays.toString(hashes)
        + ", hashThisLayerOnly="
        + Arrays.toString(hashThisLayerOnly)
        + "]";
  }
}

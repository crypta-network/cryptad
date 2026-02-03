package network.crypta.client;

import java.util.Arrays;
import java.util.Objects;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.crypt.HashResult;
import org.jetbrains.annotations.NotNull;

/**
 * Carries top-layer sizing, compatibility, and hash details for {@link Metadata}.
 *
 * <p>This value object packages the metadata fields that describe how the outermost layer should be
 * interpreted during serialization and parsing. It is typically constructed in tandem with {@link
 * MetadataRedirectTarget} or {@link SplitfilePayload} and then supplied to {@link Metadata}
 * constructors so that encoding logic can treat these values as already established. It does not
 * compute, validate, or normalize values; it simply preserves the inputs and exposes them for
 * downstream use. This makes the type suitable for call sites that already know the sizes, block
 * counts, compression intent, and hash inputs for the top layer.
 *
 * <p>Instances are immutable, but array components are not copied. Callers should treat the arrays
 * as stable for the lifetime of metadata construction and avoid mutating them after passing this
 * instance to any encoder or serializer. All numeric values represent byte counts or block counts
 * and are expected to be non-negative; consistency between sizes and block totals remains the
 * caller's responsibility. The type is safe to share across threads as long as referenced arrays
 * are not mutated.
 *
 * <ul>
 *   <li>Captures original and compressed lengths in bytes for the top layer.
 *   <li>Stores block-count signals that inform progress reporting and recovery.
 *   <li>Separates final-data hashes from optional layer-local hashes.
 * </ul>
 *
 * @see Metadata
 * @see MetadataRedirectTarget
 * @see SplitfilePayload
 */
public final class MetadataTopLayerInfo {
  private final long origDataLength;
  private final long origCompressedDataLength;
  private final int requiredBlocks;
  private final int totalBlocks;
  private final boolean topDontCompress;
  private final CompatibilityMode topCompatibilityMode;
  private final HashResult[] hashes;
  private final byte[] hashThisLayerOnly;

  /**
   * Creates a top-layer metadata info bundle from the supplied groups.
   *
   * <p>This constructor copies the scalar values out of {@code blockInfo} and assigns the hash
   * arrays from {@code hashInfo} directly, without cloning. It performs no range checks or
   * cross-field validation, so callers must ensure that byte counts, block counts, and
   * compatibility mode are coherent for the metadata they are about to serialize. Construction is
   * idempotent and side-effect free, making it suitable for repeated use at call sites that
   * precompute sizes and hashes. The referenced arrays should be treated as immutable for the
   * lifetime of the resulting instance.
   *
   * @param blockInfo sizing and block-count details for the top layer; must not be {@code null} and
   *     should contain non-negative sizes and block counts.
   * @param hashInfo hash details for the final data and/or this layer; must not be {@code null} and
   *     may contain {@code null} arrays when hashes are unavailable.
   */
  public MetadataTopLayerInfo(TopLayerBlockInfo blockInfo, TopLayerHashInfo hashInfo) {
    this.origDataLength = blockInfo.size();
    this.origCompressedDataLength = blockInfo.compressedSize();
    this.requiredBlocks = blockInfo.blocksRequired();
    this.totalBlocks = blockInfo.blocksTotal();
    this.topDontCompress = blockInfo.dontCompress();
    this.topCompatibilityMode = blockInfo.compatMode();
    this.hashes = hashInfo.hashes();
    this.hashThisLayerOnly = hashInfo.hashThisLayerOnly();
  }

  /**
   * Returns the original uncompressed size of the top layer, in bytes.
   *
   * <p>The value is returned exactly as provided at construction time and is not validated or
   * normalized. Callers commonly use {@code 0} to indicate that the size is unknown or not provided
   * for this metadata instance. The value is a byte count and is expected to be non-negative. This
   * getter is a simple accessor and has no side effects.
   *
   * @return the uncompressed top-layer byte length, or {@code 0} when unspecified by the caller.
   */
  public long origDataLength() {
    return origDataLength;
  }

  /**
   * Returns the original compressed size of the top layer, in bytes.
   *
   * <p>The value is returned exactly as provided at construction time and may be {@code 0} when the
   * compressed size is unknown, not applicable, or intentionally omitted. The value represents a
   * byte count and is expected to be non-negative. This getter does not compute compression or
   * perform any validation; it simply exposes the stored value for serialization.
   *
   * @return the compressed top-layer byte length, or {@code 0} when unspecified by the caller.
   */
  public long origCompressedDataLength() {
    return origCompressedDataLength;
  }

  /**
   * Returns the minimum number of blocks required to reconstruct the top-layer data.
   *
   * <p>This value is returned exactly as provided at construction time and is not validated against
   * {@link #totalBlocks()}. It is expected to be a non-negative block count, with {@code 0}
   * commonly used to indicate that no block data is provided. The value is used by metadata
   * serializers and progress reporting to reflect recovery requirements, but it carries no
   * enforcement here.
   *
   * @return the required top-layer block count, or {@code 0} when not supplied by the caller.
   */
  public int requiredBlocks() {
    return requiredBlocks;
  }

  /**
   * Returns the total number of blocks inserted for the top-layer data.
   *
   * <p>The value is returned as stored and is expected to be a non-negative block count, typically
   * greater than or equal to {@link #requiredBlocks()}. A value of {@code 0} is commonly used when
   * block counts are unknown or absent. This accessor does not validate any relationships or apply
   * defaults; it simply exposes the stored total for serialization and diagnostics.
   *
   * @return the total top-layer block count, or {@code 0} when not supplied by the caller.
   */
  public int totalBlocks() {
    return totalBlocks;
  }

  /**
   * Returns whether compression was intentionally disabled for the top layer.
   *
   * <p>This flag is stored exactly as provided and does not imply whether the data is actually
   * compressed; it only communicates the caller's intent for top-layer compression handling. When
   * {@code true}, metadata serializers typically record that compression was skipped. When {@code
   * false}, this type makes no additional assumptions. The value is immutable and has no side
   * effects on access.
   *
   * @return {@code true} if top-layer compression was disabled, otherwise {@code false}.
   */
  public boolean topDontCompress() {
    return topDontCompress;
  }

  /**
   * Returns the declared compatibility mode for the top layer.
   *
   * <p>The value is returned exactly as provided at construction time and is not adjusted or
   * normalized. {@link CompatibilityMode#COMPAT_UNKNOWN} is often used when the compatibility mode
   * is unknown or not specified. Callers are responsible for selecting a mode that matches the
   * metadata they intend to serialize. This accessor is a simple, side-effect-free getter.
   *
   * @return the top-layer compatibility mode supplied by the caller, possibly {@code
   *     COMPAT_UNKNOWN}.
   */
  public CompatibilityMode topCompatibilityMode() {
    return topCompatibilityMode;
  }

  /**
   * Returns the hashes of the final/original data, if provided.
   *
   * <p>The returned array reference is the same one supplied at construction time; it is not copied
   * or validated. The array may be {@code null} or empty when no hashes are available. Because the
   * array is shared, callers must treat it as immutable after construction to keep {@link #equals}
   * and {@link #hashCode} stable. This accessor does not allocate or transform the array contents.
   *
   * @return the final-data hash array, or {@code null} when no hashes were supplied.
   */
  public HashResult[] hashes() {
    return hashes;
  }

  /**
   * Returns the optional hash of only this metadata layer, if provided.
   *
   * <p>The returned array reference is the same one supplied at construction time and is not copied
   * or validated. The array may be {@code null} when a layer-local hash is unavailable or not
   * needed. Because the array is shared, callers should not mutate it after construction to avoid
   * destabilizing {@link #equals}, {@link #hashCode}, or diagnostic output.
   *
   * @return the layer-local hash bytes, or {@code null} when not supplied by the caller.
   */
  public byte[] hashThisLayerOnly() {
    return hashThisLayerOnly;
  }

  /**
   * Returns an instance representing the absence of any top-layer sizing or hash data.
   *
   * <p>The returned instance uses zero lengths and block counts, {@link
   * CompatibilityMode#COMPAT_UNKNOWN} for compatibility, and {@code null} for both hash arrays. It
   * is intended for call sites that do not have top-layer information or that want to indicate that
   * no top-layer fields should be serialized. The returned instance is immutable and safe to share
   * across threads as long as callers treat it as a constant. Callers must still avoid mutating the
   * returned arrays (which are {@code null} here) if they replace them later.
   *
   * @return a canonical "empty" top-layer info instance with no sizes or hashes.
   */
  public static MetadataTopLayerInfo none() {
    return new MetadataTopLayerInfo(
        new TopLayerBlockInfo(0, 0, 0, 0, false, CompatibilityMode.COMPAT_UNKNOWN),
        new TopLayerHashInfo(null, null));
  }

  /**
   * Compares this instance to another by value, including array contents.
   *
   * <p>The comparison checks all scalar components and uses {@link Arrays#equals(Object[],
   * Object[]) Arrays.equals} for array components, treating {@code null} arrays as equal only to
   * {@code null} arrays. This method performs a shallow comparison of array elements and does not
   * clone or normalize inputs. It is appropriate when the arrays supplied to the instance are
   * stable for the duration of comparison and should not be used if callers mutate arrays after
   * construction, because that would make equality time-dependent.
   *
   * @param o object to compare against; may be {@code null} or of another type.
   * @return {@code true} when all components, including array contents, are equal.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof MetadataTopLayerInfo other)) {
      return false;
    }
    return origDataLength == other.origDataLength
        && origCompressedDataLength == other.origCompressedDataLength
        && requiredBlocks == other.requiredBlocks
        && totalBlocks == other.totalBlocks
        && topDontCompress == other.topDontCompress
        && topCompatibilityMode == other.topCompatibilityMode
        && Arrays.equals(hashes, other.hashes)
        && Arrays.equals(hashThisLayerOnly, other.hashThisLayerOnly);
  }

  /**
   * Computes a hash code that incorporates array contents.
   *
   * <p>The hash combines scalar components with {@link Arrays#hashCode(Object[])} for array fields,
   * producing a shallow hash that depends on the current contents of the arrays. This makes the
   * hash code suitable for use as a map key only when callers do not mutate the arrays after
   * construction. The method performs no copying and assumes the instance's fields are stable. If
   * array contents are mutated later, the hash code will change and map lookups may fail.
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
   * callers should avoid mutating arrays if a stable representation is required. The returned value
   * is non-null and computed without allocating defensive copies.
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

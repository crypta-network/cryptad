package network.crypta.client;

import java.util.Arrays;
import java.util.Objects;
import network.crypta.client.Metadata.SplitfileAlgorithm;
import network.crypta.keys.ClientCHK;
import org.jetbrains.annotations.NotNull;

/**
 * Bundles splitfile layout and crypto parameters used when building metadata.
 *
 * <p>This record groups the splitfile configuration required to describe a multi-block payload in
 * {@link Metadata}. It is typically constructed alongside {@link SplitfilePayload} and {@link
 * MetadataTopLayerInfo} and then passed to {@link Metadata#Metadata(SplitfileParams,
 * SplitfilePayload, MetadataTopLayerInfo)} as a simple carrier object. The record does not validate
 * values or normalize inputs; it preserves exactly the values supplied by the caller so that
 * serialization remains predictable.
 *
 * <p>Instances are immutable, but array components are not copied. Callers should treat the array
 * contents as stable for the lifetime of metadata construction to avoid inconsistent serialization
 * or equality comparisons. All numeric values are interpreted as counts or sizes and are expected
 * to be non-negative; callers remain responsible for ensuring internal consistency across related
 * fields.
 *
 * <ul>
 *   <li>Captures per-segment sizing and optional cross-segment redundancy counts.
 *   <li>Stores per-block keys and splitfile crypto parameters.
 *   <li>Separates layout parameters from payload and top-layer details.
 * </ul>
 *
 * @param splitfileAlgorithm splitfile algorithm identifier; must match the intended encoding path.
 * @param dataURIs data block keys in block order; may be empty but not {@code null}.
 * @param checkURIs check block keys in block order; may be empty but not {@code null}.
 * @param segmentSize data blocks per typical segment, excluding cross-segment blocks; non-negative.
 * @param checkSegmentSize check blocks per typical segment, excluding cross-segment blocks.
 * @param deductBlocksFromSegments count of trailing segments with one fewer data block;
 *     non-negative.
 * @param crossSegmentBlocks cross-segment parity blocks per segment; zero when not used.
 * @param splitfileCryptoAlgorithm algorithm code applied to splitfile block encryption or routing.
 * @param splitfileCryptoKey splitfile-wide crypto key bytes; may be {@code null} for legacy modes.
 * @param specifySplitfileKey whether the crypto key is explicitly specified rather than derived.
 * @see Metadata
 * @see SplitfilePayload
 * @see MetadataTopLayerInfo
 */
@SuppressWarnings("ArrayRecordComponent")
public record SplitfileParams(
    SplitfileAlgorithm splitfileAlgorithm,
    ClientCHK[] dataURIs,
    ClientCHK[] checkURIs,
    int segmentSize,
    int checkSegmentSize,
    int deductBlocksFromSegments,
    int crossSegmentBlocks,
    byte splitfileCryptoAlgorithm,
    byte[] splitfileCryptoKey,
    boolean specifySplitfileKey) {

  /**
   * Compares this instance to another by value, including array contents.
   *
   * <p>The comparison checks all scalar components and uses {@link Arrays#equals(Object[],
   * Object[]) Arrays.equals} for array components, treating {@code null} arrays as equal only to
   * {@code null} arrays. This method performs a shallow comparison of array elements; it does not
   * clone or normalize inputs and should be used only when component arrays are stable.
   *
   * @param o object to compare against; may be {@code null} or of another type.
   * @return {@code true} when all components, including array contents, are equal.
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o
        instanceof
        SplitfileParams(
            SplitfileAlgorithm otherSplitfileAlgorithm,
            ClientCHK[] otherDataURIs,
            ClientCHK[] otherCheckURIs,
            int otherSegmentSize,
            int otherCheckSegmentSize,
            int otherDeductBlocksFromSegments,
            int otherCrossSegmentBlocks,
            byte otherSplitfileCryptoAlgorithm,
            byte[] otherSplitfileCryptoKey,
            boolean otherSpecifySplitfileKey))) {
      return false;
    }
    return splitfileAlgorithm == otherSplitfileAlgorithm
        && segmentSize == otherSegmentSize
        && checkSegmentSize == otherCheckSegmentSize
        && deductBlocksFromSegments == otherDeductBlocksFromSegments
        && crossSegmentBlocks == otherCrossSegmentBlocks
        && splitfileCryptoAlgorithm == otherSplitfileCryptoAlgorithm
        && specifySplitfileKey == otherSpecifySplitfileKey
        && Arrays.equals(dataURIs, otherDataURIs)
        && Arrays.equals(checkURIs, otherCheckURIs)
        && Arrays.equals(splitfileCryptoKey, otherSplitfileCryptoKey);
  }

  /**
   * Computes a hash code that incorporates array contents.
   *
   * <p>The hash combines scalar components with {@link Arrays#hashCode(Object[])} for the array
   * fields. As with {@link #equals(Object)}, this is a shallow hash of array elements and depends
   * on the arrays remaining stable after construction. This makes it suitable for use as a map key
   * only when callers do not mutate the arrays.
   *
   * @return a hash code derived from all components, including array contents.
   */
  @Override
  public int hashCode() {
    int result =
        Objects.hash(
            splitfileAlgorithm,
            segmentSize,
            checkSegmentSize,
            deductBlocksFromSegments,
            crossSegmentBlocks,
            splitfileCryptoAlgorithm,
            specifySplitfileKey);
    result = 31 * result + Arrays.hashCode(dataURIs);
    result = 31 * result + Arrays.hashCode(checkURIs);
    result = 31 * result + Arrays.hashCode(splitfileCryptoKey);
    return result;
  }

  /**
   * Returns a string representation that includes array contents.
   *
   * <p>The returned string lists each component in order and uses {@link Arrays#toString(Object[])}
   * for array fields. It is intended for diagnostics and logging, not for stable serialization or
   * parsing. The output will reflect the current contents of arrays at the time of the call.
   *
   * @return a non-null diagnostic string containing all component values and array contents.
   */
  @Override
  public @NotNull String toString() {
    return "SplitfileParams["
        + "splitfileAlgorithm="
        + splitfileAlgorithm
        + ", dataURIs="
        + Arrays.toString(dataURIs)
        + ", checkURIs="
        + Arrays.toString(checkURIs)
        + ", segmentSize="
        + segmentSize
        + ", checkSegmentSize="
        + checkSegmentSize
        + ", deductBlocksFromSegments="
        + deductBlocksFromSegments
        + ", crossSegmentBlocks="
        + crossSegmentBlocks
        + ", splitfileCryptoAlgorithm="
        + splitfileCryptoAlgorithm
        + ", splitfileCryptoKey="
        + Arrays.toString(splitfileCryptoKey)
        + ", specifySplitfileKey="
        + specifySplitfileKey
        + "]";
  }
}

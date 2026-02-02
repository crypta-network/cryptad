package network.crypta.client.async;

import java.io.DataInputStream;
import java.util.Arrays;
import java.util.Objects;
import network.crypta.node.KeysFetchingLocally;
import org.jetbrains.annotations.NotNull;

/**
 * Bundles parameters needed to load splitfile segments from persisted storage.
 *
 * <p>This record captures the resume-time inputs that {@link SplitFileFetcherSegmentsBuilder} needs
 * when rehydrating segment storage from a settings stream. Callers populate the full set of
 * metadata, offsets, and sizing information once, then pass the record to the builder, which
 * consumes the {@link DataInputStream} in-order and reconstructs per-segment offsets.
 *
 * <p>The record is immutable but refers to mutable collaborators such as the backing buffer and
 * segment array. It does not perform validation and assumes the supplied values describe a coherent
 * layout consistent with the persisted footer. Construct a fresh instance for each resume attempt
 * and avoid reusing it across threads because the stream is stateful.
 *
 * <ul>
 *   <li>Stores the expected block totals and checksum sizing used for validation.
 *   <li>Captures the offsets into the storage layout for key lists and segment status blocks.
 *   <li>Holds the stream and segment array that will be mutated during reconstruction.
 * </ul>
 *
 * @see SplitFileFetcherSegmentsBuilder#initSegmentsFromStream(SplitFileFetcherSegmentsLoadParams)
 */
@SuppressWarnings("java:S6206")
final class SplitFileFetcherSegmentsLoadParams {
  private final SplitFileFetcherStorage parent;
  private final int totalDataBlocks;
  private final int totalCheckBlocks;
  private final int totalCrossCheckBlocks;
  private final DataInputStream dis;
  private final boolean completeViaTruncation;
  private final KeysFetchingLocally keysFetching;
  private final SplitFileFetcherSegmentStorage[] segments;
  private final int checksumLength;
  private final boolean hasSplitfileSingleCryptoKey;
  private final long offsetKeyList;
  private final long offsetSegmentStatus;
  private final long rafLength;

  /**
   * Creates a bundle of parameters for rebuilding segments from persisted storage.
   *
   * @param parent owning storage that supplies layout constants and retry behavior.
   * @param totalDataBlocks total number of data blocks across all segments; non-negative count.
   * @param totalCheckBlocks total number of check blocks across all segments; non-negative count.
   * @param totalCrossCheckBlocks total number of cross-check blocks across all segments;
   *     non-negative count.
   * @param dis input stream positioned at the start of segment metadata; read in-order.
   * @param completeViaTruncation whether completion is recorded via file truncation semantics.
   * @param keysFetching optional helper for tracking locally fetched keys; may be {@code null}.
   * @param segments mutable segment array to populate with reconstructed storage objects.
   * @param checksumLength checksum length in bytes used for persisted checksummed blocks.
   * @param hasSplitfileSingleCryptoKey whether a single splitfile crypto key is present.
   * @param offsetKeyList byte offset of the persisted key list section in the storage layout.
   * @param offsetSegmentStatus byte offset of the persisted segment status section.
   * @param rafLength total length of the backing storage buffer in bytes.
   */
  SplitFileFetcherSegmentsLoadParams(
      SplitFileFetcherStorage parent,
      int totalDataBlocks,
      int totalCheckBlocks,
      int totalCrossCheckBlocks,
      DataInputStream dis,
      boolean completeViaTruncation,
      KeysFetchingLocally keysFetching,
      SplitFileFetcherSegmentStorage[] segments,
      int checksumLength,
      boolean hasSplitfileSingleCryptoKey,
      long offsetKeyList,
      long offsetSegmentStatus,
      long rafLength) {
    this.parent = parent;
    this.totalDataBlocks = totalDataBlocks;
    this.totalCheckBlocks = totalCheckBlocks;
    this.totalCrossCheckBlocks = totalCrossCheckBlocks;
    this.dis = dis;
    this.completeViaTruncation = completeViaTruncation;
    this.keysFetching = keysFetching;
    this.segments = segments;
    this.checksumLength = checksumLength;
    this.hasSplitfileSingleCryptoKey = hasSplitfileSingleCryptoKey;
    this.offsetKeyList = offsetKeyList;
    this.offsetSegmentStatus = offsetSegmentStatus;
    this.rafLength = rafLength;
  }

  SplitFileFetcherStorage parent() {
    return parent;
  }

  int totalDataBlocks() {
    return totalDataBlocks;
  }

  int totalCheckBlocks() {
    return totalCheckBlocks;
  }

  int totalCrossCheckBlocks() {
    return totalCrossCheckBlocks;
  }

  DataInputStream dis() {
    return dis;
  }

  boolean completeViaTruncation() {
    return completeViaTruncation;
  }

  KeysFetchingLocally keysFetching() {
    return keysFetching;
  }

  SplitFileFetcherSegmentStorage[] segments() {
    return segments;
  }

  int checksumLength() {
    return checksumLength;
  }

  boolean hasSplitfileSingleCryptoKey() {
    return hasSplitfileSingleCryptoKey;
  }

  long offsetKeyList() {
    return offsetKeyList;
  }

  long offsetSegmentStatus() {
    return offsetSegmentStatus;
  }

  long rafLength() {
    return rafLength;
  }

  /**
   * Compares this bundle to another, including array contents for segments.
   *
   * <p>The comparison uses reference equality for collaborators such as {@code parent} and {@code
   * dis}, because they represent runtime services, while {@code segments} is compared by content to
   * reflect the array's elements rather than its identity.
   *
   * @param other object to compare against; may be {@code null}.
   * @return {@code true} when all scalar fields match and segment arrays contain equal entries.
   */
  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof SplitFileFetcherSegmentsLoadParams otherParams)) {
      return false;
    }
    return completeViaTruncation == otherParams.completeViaTruncation
        && totalDataBlocks == otherParams.totalDataBlocks
        && totalCheckBlocks == otherParams.totalCheckBlocks
        && totalCrossCheckBlocks == otherParams.totalCrossCheckBlocks
        && checksumLength == otherParams.checksumLength
        && hasSplitfileSingleCryptoKey == otherParams.hasSplitfileSingleCryptoKey
        && offsetKeyList == otherParams.offsetKeyList
        && offsetSegmentStatus == otherParams.offsetSegmentStatus
        && rafLength == otherParams.rafLength
        && parent == otherParams.parent
        && dis == otherParams.dis
        && keysFetching == otherParams.keysFetching
        && Arrays.equals(segments, otherParams.segments);
  }

  /**
   * Computes a hash code that reflects scalar fields and the segment array contents.
   *
   * <p>The segment array is hashed with {@link Arrays#hashCode(Object[])}, while the remaining
   * components use {@link Objects#hash(Object...)} to preserve the record's usual behavior.
   *
   * @return hash code suitable for hash-based collections.
   */
  @Override
  public int hashCode() {
    int result =
        Objects.hash(
            parent,
            totalDataBlocks,
            totalCheckBlocks,
            totalCrossCheckBlocks,
            dis,
            completeViaTruncation,
            keysFetching,
            checksumLength,
            hasSplitfileSingleCryptoKey,
            offsetKeyList,
            offsetSegmentStatus,
            rafLength);
    result = 31 * result + Arrays.hashCode(segments);
    return result;
  }

  /**
   * Returns a human-readable string that includes the segment array contents.
   *
   * <p>The output mirrors the record component order, formatting the {@code segments} array with
   * {@link Arrays#toString(Object[])} so that its elements are visible in logs and diagnostics.
   *
   * @return non-null textual representation of the parameter bundle.
   */
  @Override
  public @NotNull String toString() {
    return "SplitFileFetcherSegmentsLoadParams["
        + "parent="
        + parent
        + ", totalDataBlocks="
        + totalDataBlocks
        + ", totalCheckBlocks="
        + totalCheckBlocks
        + ", totalCrossCheckBlocks="
        + totalCrossCheckBlocks
        + ", dis="
        + dis
        + ", completeViaTruncation="
        + completeViaTruncation
        + ", keysFetching="
        + keysFetching
        + ", segments="
        + Arrays.toString(segments)
        + ", checksumLength="
        + checksumLength
        + ", hasSplitfileSingleCryptoKey="
        + hasSplitfileSingleCryptoKey
        + ", offsetKeyList="
        + offsetKeyList
        + ", offsetSegmentStatus="
        + offsetSegmentStatus
        + ", rafLength="
        + rafLength
        + "]";
  }
}

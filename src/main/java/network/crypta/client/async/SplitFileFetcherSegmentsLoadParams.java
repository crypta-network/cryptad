package network.crypta.client.async;

import java.io.DataInputStream;
import java.util.Arrays;
import java.util.Objects;
import network.crypta.node.KeysFetchingLocally;
import org.jetbrains.annotations.NotNull;

/**
 * Bundles resume-time parameters used to load splitfile segments from persisted storage.
 *
 * <p>This class captures the inputs that {@link SplitFileFetcherSegmentsBuilder} expects when
 * rehydrating segment storage from a settings stream. Callers supply parsed settings, offsets, and
 * totals once, then pass the instance to the builder, which consumes the {@link DataInputStream} in
 * order and reconstructs per-segment offsets. The bundle itself is a simple carrier; it does not
 * validate values or normalize units, and it assumes the supplied data describes a coherent layout
 * consistent with the persisted footer.
 *
 * <p>Instances are immutable but hold references to mutable collaborators such as the backing
 * stream and the segment array that will be populated. Use a fresh instance per resume attempt and
 * avoid sharing across threads, because the stream position is stateful and the segment array is
 * mutated during reconstruction.
 *
 * <ul>
 *   <li>Holds expected block totals used later to validate reconstructed segments.
 *   <li>Captures storage offsets for key lists and segment status sections.
 *   <li>Provides the settings stream and segment array to be consumed and filled.
 * </ul>
 *
 * @see SplitFileFetcherSegmentsBuilder#initSegmentsFromStream(SplitFileFetcherSegmentsLoadParams)
 */
final class SplitFileFetcherSegmentsLoadParams {
  /** Owning storage that provides layout constants and derived values. */
  private final SplitFileFetcherStorage parent;

  /** Total number of data blocks across all segments; non-negative count. */
  private final int totalDataBlocks;

  /** Total number of check blocks across all segments; non-negative count. */
  private final int totalCheckBlocks;

  /** Total number of cross-check blocks across all segments; non-negative count. */
  private final int totalCrossCheckBlocks;

  /** Settings stream positioned at the start of segment metadata; read in order. */
  private final DataInputStream dis;

  /** Whether completion is recorded by truncating the backing storage file. */
  private final boolean completeViaTruncation;

  /** Optional helper for tracking locally fetched keys; may be {@code null}. */
  private final KeysFetchingLocally keysFetching;

  /** Mutable segment array that will be populated with reconstructed storage objects. */
  private final SplitFileFetcherSegmentStorage[] segments;

  /** Byte offset of the persisted key list section in the storage layout. */
  private final long offsetKeyList;

  /** Byte offset of the persisted segment status section in the storage layout. */
  private final long offsetSegmentStatus;

  /** Total length of the backing storage buffer in bytes. */
  private final long rafLength;

  /**
   * Creates a bundle of parameters for rebuilding segments from persisted storage.
   *
   * <p>This constructor copies totals, offsets, and the settings stream reference out of {@code
   * settings}, and retains references to runtime collaborators such as {@code parent} and {@code
   * segments}. It performs no validation and does not advance the stream. Callers are responsible
   * for ensuring the stream is positioned at the start of segment metadata, and that the supplied
   * offsets and totals match the persisted layout. The segment array is filled later by the builder
   * and must be mutable for the duration of reconstruction.
   *
   * @param parent owning storage that supplies layout constants and derived values.
   * @param settings parsed settings with totals, offsets, and settings stream.
   * @param completeViaTruncation whether completion is recorded via file truncation semantics.
   * @param keysFetching optional helper for tracking locally fetched keys; may be {@code null}.
   * @param segments mutable segment array to populate with reconstructed storage objects.
   * @param rafLength total length of the backing storage buffer in bytes.
   */
  SplitFileFetcherSegmentsLoadParams(
      SplitFileFetcherStorage parent,
      ParsedBasicSettings settings,
      boolean completeViaTruncation,
      KeysFetchingLocally keysFetching,
      SplitFileFetcherSegmentStorage[] segments,
      long rafLength) {
    this.parent = parent;
    this.totalDataBlocks = settings.getTotalDataBlocks();
    this.totalCheckBlocks = settings.getTotalCheckBlocks();
    this.totalCrossCheckBlocks = settings.getTotalCrossCheckBlocks();
    this.dis = settings.getSettingsStream();
    this.completeViaTruncation = completeViaTruncation;
    this.keysFetching = keysFetching;
    this.segments = segments;
    this.offsetKeyList = settings.getOffsetKeyList();
    this.offsetSegmentStatus = settings.getOffsetSegmentStatus();
    this.rafLength = rafLength;
  }

  /** Returns the owning storage that provides layout constants and derived values. */
  SplitFileFetcherStorage parent() {
    return parent;
  }

  /** Returns the expected total number of data blocks across all segments. */
  int totalDataBlocks() {
    return totalDataBlocks;
  }

  /** Returns the expected total number of check blocks across all segments. */
  int totalCheckBlocks() {
    return totalCheckBlocks;
  }

  /** Returns the expected total number of cross-check blocks across all segments. */
  int totalCrossCheckBlocks() {
    return totalCrossCheckBlocks;
  }

  /** Returns the settings stream positioned at the start of segment metadata. */
  DataInputStream dis() {
    return dis;
  }

  /** Returns {@code true} when completion is recorded by truncating the backing storage file. */
  boolean completeViaTruncation() {
    return completeViaTruncation;
  }

  /** Returns the optional helper used to track locally fetched keys, or {@code null}. */
  KeysFetchingLocally keysFetching() {
    return keysFetching;
  }

  /** Returns the mutable segment array to be populated by the builder. */
  SplitFileFetcherSegmentStorage[] segments() {
    return segments;
  }

  /** Returns the checksum length in bytes as provided by the owning storage. */
  int checksumLength() {
    return parent.checksumLength;
  }

  /** Returns {@code true} if the splitfile has a single shared crypto key. */
  boolean hasSplitfileSingleCryptoKey() {
    return parent.splitfileSingleCryptoKey != null;
  }

  /** Returns the byte offset of the persisted key list section. */
  long offsetKeyList() {
    return offsetKeyList;
  }

  /** Returns the byte offset of the persisted segment status section. */
  long offsetSegmentStatus() {
    return offsetSegmentStatus;
  }

  /** Returns the total length of the backing storage buffer in bytes. */
  long rafLength() {
    return rafLength;
  }

  /**
   * Compares this bundle to another, including array contents for segments.
   *
   * <p>The comparison uses reference equality for collaborators such as {@code parent} and {@code
   * dis}, because they represent runtime services, while {@code segments} is compared by content to
   * reflect the array's elements rather than its identity. The comparison does not attempt to
   * compare stream positions or external storage state; it only compares the values stored in this
   * instance and the references it holds.
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
        && checksumLength() == otherParams.checksumLength()
        && hasSplitfileSingleCryptoKey() == otherParams.hasSplitfileSingleCryptoKey()
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
   * components use {@link Objects#hash(Object...)}. This matches the equality contract used by
   * {@link #equals(Object)} and ensures that instances used as keys in hash-based collections
   * remain consistent with their contained values and references.
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
            checksumLength(),
            hasSplitfileSingleCryptoKey(),
            offsetKeyList,
            offsetSegmentStatus,
            rafLength);
    result = 31 * result + Arrays.hashCode(segments);
    return result;
  }

  /**
   * Returns a human-readable string that includes the segment array contents.
   *
   * <p>The output mirrors the component order of this bundle, formatting the {@code segments} array
   * with {@link Arrays#toString(Object[])} so that its elements are visible in logs and
   * diagnostics. The resulting string is intended for debugging and should not be parsed or relied
   * upon for stable serialization.
   *
   * @return non-null textual representation of the parameter bundle.
   */
  @Override
  public @NotNull String toString() {
    SplitFileFetcherStorage parentRef = parent;
    int checksumLengthValue = parentRef == null ? 0 : parentRef.checksumLength;
    boolean hasSplitfileSingleCryptoKeyValue =
        parentRef != null && parentRef.splitfileSingleCryptoKey != null;

    return "SplitFileFetcherSegmentsLoadParams["
        + "parent="
        + (parentRef == null ? "null" : java.util.Objects.toIdentityString(parentRef))
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
        + checksumLengthValue
        + ", hasSplitfileSingleCryptoKey="
        + hasSplitfileSingleCryptoKeyValue
        + ", offsetKeyList="
        + offsetKeyList
        + ", offsetSegmentStatus="
        + offsetSegmentStatus
        + ", rafLength="
        + rafLength
        + "]";
  }
}

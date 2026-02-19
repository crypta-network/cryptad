package network.crypta.client.async;

import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.keys.CHKBlock;

/**
 * Computes size totals and validates splitfile metadata for fetcher storage layouts.
 *
 * <p>This package-private helper concentrates the calculations that derive persisted lengths from
 * segment keys and configuration flags. It is intentionally stateless: every method is a pure
 * computation or validation based on the provided arguments, making it safe to call repeatedly
 * during planning and preflight validation. The layout math assumes that segment arrays already
 * encode the final data/check block counts per segment, including any cross-check blocks that must
 * be removed before reporting the user-visible data block total.
 *
 * <p>Typical usage is to precompute storage sizes before allocating persistent files and to perform
 * lightweight sanity checks on metadata lengths. The methods do not synchronize and do not retain
 * references to inputs; callers are responsible for ensuring consistent inputs across segments.
 *
 * <ul>
 *   <li>Aggregates per-segment sizes into a single storage summary.
 *   <li>Validates metadata length expectations before starting a fetch.
 *   <li>Enforces minimal structural invariants such as a positive segment count.
 * </ul>
 */
final class SplitFileFetcherStorageLayout {
  /** Prevents instantiation; this type is a static utility holder for layout computations. */
  private SplitFileFetcherStorageLayout() {}

  /**
   * Immutable totals derived from segment keys and storage configuration inputs.
   *
   * <p>Each component reflects an aggregate across all segments and uses byte counts where noted.
   * The record is intentionally small and value-like so that callers can pass it between planning
   * and persistence steps without additional bookkeeping.
   *
   * @param splitfileDataBlocks total data blocks after cross-check blocks are excluded
   * @param splitfileCheckBlocks total check blocks across all segments in the splitfile
   * @param storedKeysLength total stored key bytes required for all segment key material
   * @param storedSegmentStatusLength total stored segment status bytes including padding
   */
  record AccumulatedSizes(
      int splitfileDataBlocks,
      int splitfileCheckBlocks,
      long storedKeysLength,
      long storedSegmentStatusLength) {}

  /**
   * Aggregates per-segment sizes into a single storage summary for the splitfile.
   *
   * <p>The calculation walks each segment entry, summing data and check blocks, stored key lengths,
   * and stored segment status lengths. Cross-check blocks are counted while iterating, then removed
   * once at the end so that the returned data block count reflects the effective payload size. The
   * method is deterministic and has no side effects, so callers can reuse it to recompute totals
   * when the configuration changes.
   *
   * <pre>{@code
   * SplitFileFetcherStorageLayout.AccumulatedSizes sizes =
   *     SplitFileFetcherStorageLayout.accumulateSizes(keys, crossChecks, singleKey, checksum, -1,
   *         persistent);
   * }</pre>
   *
   * @param segmentKeys non-null array of segment key descriptors to aggregate
   * @param crossCheckBlocks non-negative cross-check blocks per segment to subtract from data
   * @param hasSplitfileSingleCryptoKey true when all segments share one crypto key
   * @param checksumLength checksum length in bytes used for persisted segment metadata
   * @param maxRetries maximum retry count, or {@code -1} when unbounded or unset
   * @param persistent true when lengths target persistent storage rather than transient buffers
   * @return aggregate sizes for blocks, key storage, and segment status storage
   */
  static AccumulatedSizes accumulateSizes(
      SplitFileSegmentKeys[] segmentKeys,
      int crossCheckBlocks,
      boolean hasSplitfileSingleCryptoKey,
      int checksumLength,
      int maxRetries,
      boolean persistent) {
    int splitfileDataBlocks = 0;
    int splitfileCheckBlocks = 0;
    long storedKeysLength = 0;
    long storedSegmentStatusLength = 0;
    for (SplitFileSegmentKeys keys : segmentKeys) {
      int dataBlocks = keys.getDataBlocks();
      int checkBlocks = keys.getCheckBlocks();
      splitfileDataBlocks += dataBlocks;
      splitfileCheckBlocks += checkBlocks;
      storedKeysLength +=
          SplitFileFetcherSegmentStorage.storedKeysLength(
              dataBlocks, checkBlocks, hasSplitfileSingleCryptoKey, checksumLength);
      storedSegmentStatusLength +=
          SplitFileFetcherSegmentStorage.paddedStoredSegmentStatusLength(
              dataBlocks - crossCheckBlocks,
              checkBlocks,
              crossCheckBlocks,
              maxRetries != -1,
              checksumLength,
              persistent);
    }
    // Subtract cross-check blocks from data blocks to get the actual data blocks.
    splitfileDataBlocks -= segmentKeys.length * crossCheckBlocks;
    return new AccumulatedSizes(
        splitfileDataBlocks, splitfileCheckBlocks, storedKeysLength, storedSegmentStatusLength);
  }

  /**
   * Validates that the stored check length is not materially larger than the final length.
   *
   * <p>The comparison allows a small difference of up to one data block length to tolerate rounding
   * effects during metadata assembly. When the excess exceeds that tolerance, a fetch exception is
   * raised to prevent fetchers from trusting malformed metadata. The method performs only the
   * length comparison and does not mutate state or record diagnostics.
   *
   * @param checkLength reported check-length value in bytes from splitfile metadata
   * @param finalLength expected final length in bytes derived from segment information
   * @throws FetchException when the check length exceeds the final length beyond tolerance
   */
  static void validateCheckLength(long checkLength, long finalLength) throws FetchException {
    if (checkLength > finalLength && checkLength - finalLength > CHKBlock.DATA_LENGTH)
      throw new FetchException(
          FetchExceptionMode.INVALID_METADATA,
          "Splitfile is " + checkLength + " bytes long but length is " + finalLength + " bytes");
  }

  /**
   * Ensures a splitfile describes at least one segment before processing begins.
   *
   * <p>This is a defensive check used in assertion-heavy paths. It treats a non-positive segment
   * count as a programmer error rather than user input and therefore throws an {@link
   * AssertionError}. The method does not return a value and does not attempt to recover.
   *
   * @param segmentCount number of segments that the splitfile metadata declares
   * @throws AssertionError when {@code segmentCount} is zero or negative
   */
  static void validateSegmentCount(int segmentCount) {
    if (segmentCount <= 0) {
      throw new AssertionError("A splitfile has to have at least one segment");
    }
  }
}

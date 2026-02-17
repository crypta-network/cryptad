package network.crypta.client.async;

import java.io.DataInputStream;
import java.io.IOException;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.Metadata;
import network.crypta.keys.CHKBlock;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.support.io.StorageFormatException;

/**
 * Builds splitfile segment storage objects for new and resumed fetches.
 *
 * <p>This stateless helper centralizes the offset calculations and segment instantiation performed
 * during splitfile storage setup. Callers assemble either a {@link SegmentsBuildContext} for the
 * fresh-download path or a {@link SplitFileFetcherSegmentsLoadParams} bundle for the resume path
 * and then invoke the corresponding initializer. Each initializer walks the segment list, computes
 * per-segment offsets, validates counts against expected totals, and wires cross-segment helpers so
 * that the surrounding {@link SplitFileFetcherStorage} can schedule work without duplicating layout
 * math.
 *
 * <p>The builder does not retain a mutable state between calls; thread safety therefore depends on
 * the provided storage, arrays, and key listeners. Inputs are expected to be consistent with the
 * splitfile metadata and persisted layout, and the methods enforce this with validation and
 * assertions rather than defensive copying.
 *
 * <ul>
 *   <li>Compute per-segment offsets and stored lengths for the fetcher layout.
 *   <li>Construct segment and cross-segment storage helpers.
 *   <li>Register keys with the fetcher key listener for scheduling.
 * </ul>
 *
 * @see SplitFileFetcherStorage
 * @see SplitFileFetcherSegmentsLoadParams
 */
final class SplitFileFetcherSegmentsBuilder {
  /** Hidden utility constructor for a static-only helper. */
  private SplitFileFetcherSegmentsBuilder() {}

  /**
   * Mutable context bag for building segments from in-memory metadata.
   *
   * <p>Callers populate the fields before invoking {@link
   * #initSegmentsAndKeys(SegmentsBuildContext)}. The instance is consumed as-is, so all arrays,
   * offsets, and sizing metadata must already describe a coherent splitfile layout.
   *
   * <p>The default constructor performs no validation and leaves all fields unset. Callers are
   * responsible for filling each field before handing the instance to the builder.
   *
   * @see #initSegmentsAndKeys(SegmentsBuildContext)
   */
  static final class SegmentsBuildContext {
    /** Creates an empty context to be populated before initialization. */
    SegmentsBuildContext() {}

    /** Owning storage used for offsets, logging, and key registration. */
    SplitFileFetcherStorage parent;

    /** Target array that receives constructed segment storage instances. */
    SplitFileFetcherSegmentStorage[] segments;

    /** Segment key metadata aligned with the segment array. */
    SplitFileSegmentKeys[] segmentKeys;

    /** Splitfile metadata used to allocate cross-segment helpers. */
    Metadata metadata;

    /** Number of cross-check blocks per segment; used in sizing and offsets. */
    int crossCheckBlocks;

    /** Expected data blocks per segment as reported by metadata. */
    int blocksPerSegment;

    /** Original fetch context supplying policy limits for segment sizing. */
    FetchContext origFetchContext;

    /** Salting helper used when registering segment keys with the listener. */
    KeySalter salt;

    /** Optional helper for marking keys as being fetched locally. */
    KeysFetchingLocally keysFetching;

    /** Accumulated sizes for keys and status persisted in the storage layout. */
    SplitFileFetcherStorageLayout.AccumulatedSizes acc;

    /** Total stored data length in bytes for data blocks (excluding truncation). */
    long storedBlocksLength;

    /** Total stored cross-check length in bytes when truncation completes. */
    long storedCrossCheckBlocksLength;

    /** Whether the persisted layout uses truncation to mark completion. */
    boolean completeViaTruncation;

    /** Whether the storage is persistent and should write resume metadata. */
    boolean persistent;

    /** Whether a single splitfile crypto key is present for stored key lengths. */
    boolean hasSplitfileSingleCryptoKey;

    /** Length in bytes of the checksum appended to stored metadata. */
    int checksumLength;
  }

  /**
   * Initializes segment storage and registers keys for a new splitfile fetch.
   *
   * <p>The method walks each {@link SplitFileSegmentKeys} entry, calculates offsets for stored
   * segment data and metadata, validates per-segment limits from the original fetch context, and
   * then creates {@link SplitFileFetcherSegmentStorage} instances with the computed values. It also
   * registers each segment key with the parent key listener so that later scheduling can rely on
   * fully populated Bloom filters.
   *
   * <p>The caller must provide a fully-populated {@link SegmentsBuildContext}. The method assumes
   * the segment arrays and metadata are consistent; violations surface through assertions or a
   * {@link FetchException}. This initializer is not idempotent because it allocates storage helpers
   * and registers keys each time it runs.
   *
   * @param ctx container holding metadata, arrays, offsets, and policy settings; must describe a
   *     consistent splitfile layout and remain non-null during the call.
   * @return newly built segment and cross-segment storage helpers for the fetcher to use.
   * @throws FetchException when segment sizes exceed fetch policy limits or metadata is invalid.
   */
  static SplitFileFetcherSegmentsInit initSegmentsAndKeys(SegmentsBuildContext ctx)
      throws FetchException {
    long dataOffset = 0;
    long crossCheckBlocksOffset = ctx.storedBlocksLength; // Only used if completeViaTruncation
    long segmentKeysOffset = ctx.parent.offsetKeyList;
    long segmentStatusOffset = ctx.parent.offsetSegmentStatus;

    for (int i = 0; i < ctx.segments.length; i++) {
      SplitFileSegmentKeys keys = ctx.segmentKeys[i];
      final int dataBlocks = keys.getDataBlocks() - ctx.crossCheckBlocks;
      final int checkBlocks = keys.getCheckBlocks();
      validateBlocksPerSegmentLimit(ctx.origFetchContext, dataBlocks, checkBlocks);
      SplitFileFetcherSegmentStorage.InitParams p = new SplitFileFetcherSegmentStorage.InitParams();
      p.parent = ctx.parent;
      p.segNumber = i;
      p.dataBlocks = dataBlocks;
      p.checkBlocks = checkBlocks;
      p.crossCheckBlocks = ctx.crossCheckBlocks;
      p.segmentDataOffset = dataOffset;
      p.segmentCrossCheckDataOffset = ctx.completeViaTruncation ? crossCheckBlocksOffset : -1;
      p.segmentKeysOffset = segmentKeysOffset;
      p.segmentStatusOffset = segmentStatusOffset;
      p.writeRetries = ctx.parent.maxRetries != -1;
      p.keys = keys;
      p.keysFetching = ctx.keysFetching;
      ctx.segments[i] = new SplitFileFetcherSegmentStorage(p);
      dataOffset += (long) dataBlocks * CHKBlock.DATA_LENGTH;
      if (!ctx.completeViaTruncation) {
        dataOffset += (long) ctx.crossCheckBlocks * CHKBlock.DATA_LENGTH;
      } else {
        crossCheckBlocksOffset += (long) ctx.crossCheckBlocks * CHKBlock.DATA_LENGTH;
      }
      segmentKeysOffset +=
          SplitFileFetcherSegmentStorage.storedKeysLength(
              dataBlocks + ctx.crossCheckBlocks,
              checkBlocks,
              ctx.hasSplitfileSingleCryptoKey,
              ctx.checksumLength);
      segmentStatusOffset +=
          SplitFileFetcherSegmentStorage.paddedStoredSegmentStatusLength(
              dataBlocks,
              checkBlocks,
              ctx.crossCheckBlocks,
              ctx.parent.maxRetries != -1,
              ctx.checksumLength,
              ctx.persistent);
      for (int j = 0; j < (dataBlocks + ctx.crossCheckBlocks + checkBlocks); j++) {
        ctx.parent.keyListener.addKey(keys.getKey(j, null, false).getNodeKey(false), i, ctx.salt);
      }
      debugSegmentOffsets(ctx.parent, i, ctx.segments[i]);
    }
    assert (dataOffset == ctx.storedBlocksLength);
    assert !ctx.completeViaTruncation
        || (crossCheckBlocksOffset == ctx.storedCrossCheckBlocksLength + ctx.storedBlocksLength);
    assert (segmentKeysOffset
        == ctx.storedBlocksLength + ctx.storedCrossCheckBlocksLength + ctx.acc.storedKeysLength());
    assert (segmentStatusOffset
        == ctx.storedBlocksLength
            + ctx.storedCrossCheckBlocksLength
            + ctx.acc.storedKeysLength()
            + ctx.acc.storedSegmentStatusLength());

    // Lie about the required number of blocks. See the original inline comment for rationale.
    int totalCrossCheckBlocks = ctx.segmentKeys.length * ctx.crossCheckBlocks;
    ctx.parent.fetcher.setSplitfileBlocks(
        ctx.acc.splitfileDataBlocks() + totalCrossCheckBlocks, ctx.acc.splitfileCheckBlocks());

    ctx.parent.keyListener.finishedSetup();

    SplitFileFetcherCrossSegmentStorage[] crossSegments =
        SplitFileFetcherCrossSegmentAllocator.createCrossSegments(
            ctx.parent,
            ctx.metadata,
            ctx.crossCheckBlocks,
            ctx.blocksPerSegment,
            ctx.segments,
            ctx.parent.fecCodec);
    return new SplitFileFetcherSegmentsInit(ctx.segments, crossSegments, null);
  }

  /**
   * Reconstructs segment storage from a persisted settings stream.
   *
   * <p>This method reads per-segment metadata from the supplied {@link DataInputStream}, computes
   * the layout offsets expected by the persisted storage format, and instantiates each {@link
   * SplitFileFetcherSegmentStorage} in the provided array. After all segments are loaded, it
   * validates the accumulated block totals and reads any cross-segment metadata that follows in the
   * stream, returning the resulting storage bundle.
   *
   * <p>The {@link SplitFileFetcherSegmentsLoadParams} input must reflect the persisted layout,
   * including offsets and total counts. The method consumes the stream in order and is therefore
   * not idempotent; callers should pass a stream positioned at the start of segment metadata.
   *
   * @param params bundle of storage, offsets, totals, and stream state used to reconstruct
   *     segments; must not be null and must reference the same splitfile layout as the persisted
   *     data.
   * @return initialized segment and cross-segment storages plus the remaining stream position.
   * @throws StorageFormatException when persisted, data is inconsistent with expected totals.
   * @throws IOException when the underlying stream cannot be read.
   */
  static SplitFileFetcherSegmentsInit initSegmentsFromStream(
      SplitFileFetcherSegmentsLoadParams params) throws StorageFormatException, IOException {
    SplitFileFetcherStorage parent = params.parent();
    int totalDataBlocks = params.totalDataBlocks();
    int totalCheckBlocks = params.totalCheckBlocks();
    int totalCrossCheckBlocks = params.totalCrossCheckBlocks();
    DataInputStream dis = params.dis();
    boolean completeViaTruncation = params.completeViaTruncation();
    KeysFetchingLocally keysFetching = params.keysFetching();
    SplitFileFetcherSegmentStorage[] segments = params.segments();
    int checksumLength = params.checksumLength();
    boolean hasSplitfileSingleCryptoKey = params.hasSplitfileSingleCryptoKey();
    long offsetKeyList = params.offsetKeyList();
    long offsetSegmentStatus = params.offsetSegmentStatus();
    long rafLength = params.rafLength();

    long dataOffset = 0;
    long crossCheckBlocksOffset =
        completeViaTruncation ? (long) totalDataBlocks * CHKBlock.DATA_LENGTH : 0;
    long segmentKeysOffset = offsetKeyList;
    long segmentStatusOffset = offsetSegmentStatus;
    int countDataBlocks = 0;
    int countCheckBlocks = 0;
    int countCrossCheckBlocks = 0;
    for (int i = 0; i < segments.length; i++) {
      SplitFileFetcherSegmentStorage.LoadParams lp =
          new SplitFileFetcherSegmentStorage.LoadParams();
      lp.parent = parent;
      lp.dis = dis;
      lp.segNo = i;
      lp.writeRetries = parent.maxRetries != -1;
      lp.segmentDataOffset = dataOffset;
      lp.segmentCrossCheckDataOffset = completeViaTruncation ? crossCheckBlocksOffset : -1;
      lp.segmentKeysOffset = segmentKeysOffset;
      lp.segmentStatusOffset = segmentStatusOffset;
      lp.keysFetching = keysFetching;
      segments[i] = new SplitFileFetcherSegmentStorage(lp);
      int dataBlocks = segments[i].dataBlocks;
      countDataBlocks += dataBlocks;
      int checkBlocks = segments[i].checkBlocks;
      countCheckBlocks += checkBlocks;
      int crossCheckBlocks = segments[i].crossSegmentCheckBlocks;
      countCrossCheckBlocks += crossCheckBlocks;
      dataOffset += (long) dataBlocks * CHKBlock.DATA_LENGTH;
      if (completeViaTruncation)
        crossCheckBlocksOffset += (long) crossCheckBlocks * CHKBlock.DATA_LENGTH;
      else dataOffset += (long) crossCheckBlocks * CHKBlock.DATA_LENGTH;
      segmentKeysOffset +=
          SplitFileFetcherSegmentStorage.storedKeysLength(
              dataBlocks + crossCheckBlocks,
              checkBlocks,
              hasSplitfileSingleCryptoKey,
              checksumLength);
      segmentStatusOffset +=
          SplitFileFetcherSegmentStorage.paddedStoredSegmentStatusLength(
              dataBlocks,
              checkBlocks,
              crossCheckBlocks,
              parent.maxRetries != -1,
              checksumLength,
              true);
      validateSegmentOffsets(dataOffset, segments[i], rafLength);
      debugSegmentOffsets(parent, i, segments[i]);
    }
    validateTotals(
        countDataBlocks,
        totalDataBlocks,
        countCheckBlocks,
        totalCheckBlocks,
        countCrossCheckBlocks,
        totalCrossCheckBlocks);

    int crossSegmentsCount = dis.readInt();
    SplitFileFetcherCrossSegmentStorage[] crossSegmentsLocal =
        (crossSegmentsCount == 0)
            ? null
            : new SplitFileFetcherCrossSegmentStorage[crossSegmentsCount];
    for (int i = 0; i < crossSegmentsCount; i++) {
      // crossSegmentsLocal is non-null when crossSegmentsCount > 0
      crossSegmentsLocal[i] = new SplitFileFetcherCrossSegmentStorage(parent, i, dis);
    }
    return new SplitFileFetcherSegmentsInit(segments, crossSegmentsLocal, dis);
  }

  /**
   * Validates that counted blocks match the expected totals from persisted metadata.
   *
   * @param countDataBlocks number of data blocks tallied from loaded segments.
   * @param totalDataBlocks expected total data blocks from the settings header.
   * @param countCheckBlocks number of check blocks tallied from loaded segments.
   * @param totalCheckBlocks expected total check blocks from the settings header.
   * @param countCrossCheckBlocks number of cross-check blocks tallied from loaded segments.
   * @param totalCrossCheckBlocks expected total cross-check blocks from the settings header.
   * @throws StorageFormatException when any of the totals differ from the expected values.
   */
  private static void validateTotals(
      int countDataBlocks,
      int totalDataBlocks,
      int countCheckBlocks,
      int totalCheckBlocks,
      int countCrossCheckBlocks,
      int totalCrossCheckBlocks)
      throws StorageFormatException {
    if (countDataBlocks != totalDataBlocks)
      throw new StorageFormatException(
          "Total data blocks " + countDataBlocks + " but expected " + totalDataBlocks);
    if (countCheckBlocks != totalCheckBlocks)
      throw new StorageFormatException(
          "Total check blocks " + countCheckBlocks + " but expected " + totalCheckBlocks);
    if (countCrossCheckBlocks != totalCrossCheckBlocks)
      throw new StorageFormatException(
          "Total cross-check blocks "
              + countCrossCheckBlocks
              + " but expected "
              + totalCrossCheckBlocks);
  }

  /**
   * Logs computed offsets for a segment when debug logging is enabled.
   *
   * @param parent storage owner used for logging context; must not be null.
   * @param index zero-based segment index being reported.
   * @param segment segment whose data and cross-check offsets are logged.
   */
  private static void debugSegmentOffsets(
      SplitFileFetcherStorage parent, int index, SplitFileFetcherSegmentStorage segment) {
    if (SplitFileFetcherStorage.LOG.isDebugEnabled()) {
      SplitFileFetcherStorage.LOG.debug(
          "Segment {}: data blocks offset {} cross-check blocks offset {} for segment {} of {}",
          index,
          segment.segmentBlockDataOffset,
          segment.segmentCrossCheckBlockDataOffset,
          index,
          parent);
    }
  }

  /**
   * Ensures the computed segment offsets do not extend past the backing file length.
   *
   * @param dataOffset next data offset after the segment's data blocks, in bytes.
   * @param segment segment whose cross-check offset is validated.
   * @param rafLength total length of the backing file, in bytes.
   * @throws StorageFormatException when computed, offsets exceed the file length.
   */
  private static void validateSegmentOffsets(
      long dataOffset, SplitFileFetcherSegmentStorage segment, long rafLength)
      throws StorageFormatException {
    if (dataOffset > rafLength)
      throw new StorageFormatException(
          "Data offset past end of file " + dataOffset + " of " + rafLength);
    if (segment.segmentCrossCheckBlockDataOffset > rafLength)
      throw new StorageFormatException(
          "Cross-check blocks offset past end of file "
              + segment.segmentCrossCheckBlockDataOffset
              + " of "
              + rafLength);
  }

  /**
   * Validates per-segment data and check block counts against the original fetch policy.
   *
   * @param origFetchContext original fetch context providing block limit configuration.
   * @param blocksPerSegment number of data blocks for the segment being constructed.
   * @param checkBlocksPerSegment number of check blocks for the segment being constructed.
   * @throws FetchException when either data or check block count exceeds configured limits.
   */
  private static void validateBlocksPerSegmentLimit(
      FetchContext origFetchContext, int blocksPerSegment, int checkBlocksPerSegment)
      throws FetchException {
    if ((blocksPerSegment > origFetchContext.getMaxDataBlocksPerSegment())
        || (checkBlocksPerSegment > origFetchContext.getMaxCheckBlocksPerSegment())) {
      throw new FetchException(
          FetchExceptionMode.TOO_MANY_BLOCKS_PER_SEGMENT,
          "Too many blocks per segment: "
              + blocksPerSegment
              + " data, "
              + checkBlocksPerSegment
              + " check");
    }
  }
}

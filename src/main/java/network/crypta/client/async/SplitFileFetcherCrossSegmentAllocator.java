package network.crypta.client.async;

import java.util.Random;
import network.crypta.client.FECCodec;
import network.crypta.client.Metadata;
import network.crypta.support.math.MersenneTwister;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Allocates cross-segment storage blocks for splitfile fetches.
 *
 * <p>This utility builds the cross-segment layout used during fetch by choosing, per cross segment,
 * a set of data and check blocks sourced from the per-segment storage structures. The allocation is
 * driven by a deterministic random stream seeded from {@link Metadata} so a given metadata set
 * yields the same allocation pattern while still spreading blocks across segments.
 *
 * <p>The allocator is intentionally stateless: it creates new {@link
 * SplitFileFetcherCrossSegmentStorage} instances and mutates the provided {@link
 * SplitFileFetcherSegmentStorage} instances to reserve blocks. Callers should treat the operation
 * as single-threaded with exclusive ownership of the storage objects for the duration of the call.
 * The method performs bounded randomized probes before falling back to a linear scan and throws an
 * {@link IllegalStateException} if no block can be reserved.
 *
 * <ul>
 *   <li>Creates cross-segment storage objects with correct per-segment sizing.
 *   <li>Reserves data and check blocks in backing segment storages.
 *   <li>Logs allocation progress for fetch diagnostics and troubleshooting.
 * </ul>
 *
 * @see SplitFileFetcherCrossSegmentStorage
 * @see SplitFileFetcherSegmentStorage
 */
final class SplitFileFetcherCrossSegmentAllocator {
  /** Logger for allocation progress and allocation failure diagnostics. */
  private static final Logger LOG =
      LoggerFactory.getLogger(SplitFileFetcherCrossSegmentAllocator.class);

  /**
   * Creates and populates cross-segment storages for a splitfile fetch.
   *
   * <p>When {@code crossCheckBlocks} is zero this returns an empty array without touching the
   * segment storages. Otherwise, it seeds a deterministic random source from the metadata, creates
   * one cross segment per input segment, and reserves {@code blocksPerSegment} data blocks and
   * {@code crossCheckBlocks} check blocks for each cross segment. If the metadata indicates that
   * blocks must be deducted, the size is reduced for the last {@code
   * metadata.getDeductBlocksFromSegments()} segments. Allocation uses bounded random probes
   * followed by a linear scan; failure to reserve any block results in {@link
   * IllegalStateException}.
   *
   * @param owner fetcher storage that owns the cross-segment allocations; must be non-null
   * @param metadata splitfile metadata supplying hashes and allocation adjustments; must be
   *     non-null
   * @param crossCheckBlocks number of check blocks per cross segment; zero disables cross segments
   * @param blocksPerSegment number of data blocks per cross segment before deductions are applied
   * @param segments per-segment storage array supplying allocators and block slots; must be
   *     non-null
   * @param fecCodec FEC codec used by cross segments for encoding and bookkeeping; must be non-null
   * @return array of cross-segment storages; empty when crossCheckBlocks is zero
   * @throws IllegalStateException if no segment can supply a required block after probing
   */
  static SplitFileFetcherCrossSegmentStorage[] createCrossSegments(
      SplitFileFetcherStorage owner,
      Metadata metadata,
      int crossCheckBlocks,
      int blocksPerSegment,
      SplitFileFetcherSegmentStorage[] segments,
      FECCodec fecCodec) {
    if (crossCheckBlocks == 0) return new SplitFileFetcherCrossSegmentStorage[0];
    Random crossSegmentRandom =
        MersenneTwister.createUnsynchronized(
            Metadata.getCrossSegmentSeed(metadata.getHashes(), metadata.getHashThisLayerOnly()));
    SplitFileFetcherCrossSegmentStorage[] xSegments =
        new SplitFileFetcherCrossSegmentStorage[segments.length];
    int segLen = blocksPerSegment;
    int deductBlocksFromSegments = metadata.getDeductBlocksFromSegments();
    for (int i = 0; i < xSegments.length; i++) {
      LOG.info("Allocating blocks (on fetch) for cross segment {}", i);
      if (segments.length - i == deductBlocksFromSegments) {
        segLen--;
      }
      SplitFileFetcherCrossSegmentStorage seg =
          new SplitFileFetcherCrossSegmentStorage(i, segLen, crossCheckBlocks, owner, fecCodec);
      xSegments[i] = seg;
      for (int j = 0; j < segLen; j++) {
        allocateCrossDataBlock(seg, crossSegmentRandom, segments);
      }
      for (int j = 0; j < crossCheckBlocks; j++) {
        allocateCrossCheckBlock(seg, crossSegmentRandom, segments);
      }
    }
    return xSegments;
  }

  /**
   * Reserves one data block mapping for a cross segment.
   *
   * <p>The allocator first attempts up to ten randomized probes across the segment array, then
   * scans linearly to find an available block. On success, it records the mapping in the cross
   * segment; otherwise it fails fast to signal allocator exhaustion.
   *
   * @param segment cross-segment storage receiving the reserved data block mapping
   * @param random random source used to select candidate segments for allocation
   * @param segments backing segment storages that may supply a data block
   * @throws IllegalStateException if no segment can provide a data block after probing
   */
  private static void allocateCrossDataBlock(
      SplitFileFetcherCrossSegmentStorage segment,
      Random random,
      SplitFileFetcherSegmentStorage[] segments) {
    int x = 0;
    for (int i = 0; i < 10; i++) {
      x = random.nextInt(segments.length);
      SplitFileFetcherSegmentStorage seg = segments[x];
      int blockNum = seg.allocateCrossDataBlock(segment, random);
      if (blockNum >= 0) {
        segment.addDataBlock(seg, blockNum);
        return;
      }
    }
    for (int i = 0; i < segments.length; i++) {
      x++;
      if (x == segments.length) x = 0;
      SplitFileFetcherSegmentStorage seg = segments[x];
      int blockNum = seg.allocateCrossDataBlock(segment, random);
      if (blockNum >= 0) {
        segment.addDataBlock(seg, blockNum);
        return;
      }
    }
    throw new IllegalStateException("Unable to allocate cross data block!");
  }

  /**
   * Reserves one check block mapping for a cross segment.
   *
   * <p>The allocator uses randomized probes followed by a linear scan to locate an available check
   * block. Successful allocation records the mapping in the cross segment; failure indicates the
   * allocator cannot satisfy the requested check block count.
   *
   * @param segment cross-segment storage receiving the reserved check block mapping
   * @param random random source used to select candidate segments for allocation
   * @param segments backing segment storages that may supply a check block
   * @throws IllegalStateException if no segment can provide a check block after probing
   */
  private static void allocateCrossCheckBlock(
      SplitFileFetcherCrossSegmentStorage segment,
      Random random,
      SplitFileFetcherSegmentStorage[] segments) {
    int x = 0;
    for (int i = 0; i < 10; i++) {
      x = random.nextInt(segments.length);
      SplitFileFetcherSegmentStorage seg = segments[x];
      int blockNum = seg.allocateCrossCheckBlock(segment, random);
      if (blockNum >= 0) {
        segment.addDataBlock(seg, blockNum);
        return;
      }
    }
    for (int i = 0; i < segments.length; i++) {
      x++;
      if (x == segments.length) x = 0;
      SplitFileFetcherSegmentStorage seg = segments[x];
      int blockNum = seg.allocateCrossCheckBlock(segment, random);
      if (blockNum >= 0) {
        segment.addDataBlock(seg, blockNum);
        return;
      }
    }
    throw new IllegalStateException("Unable to allocate cross data block!");
  }

  /** Prevents instantiation of this utility class. */
  private SplitFileFetcherCrossSegmentAllocator() {}
}

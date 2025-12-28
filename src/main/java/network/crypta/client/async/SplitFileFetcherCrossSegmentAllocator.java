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
 * <p>Separates the random allocation logic from storage bookkeeping.
 */
final class SplitFileFetcherCrossSegmentAllocator {
  private static final Logger LOG =
      LoggerFactory.getLogger(SplitFileFetcherCrossSegmentAllocator.class);

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

  /** Reserved for future use. */
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

  /** Reserved for future use. */
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

  private SplitFileFetcherCrossSegmentAllocator() {}
}

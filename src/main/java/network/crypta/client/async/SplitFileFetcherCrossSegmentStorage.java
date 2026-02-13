package network.crypta.client.async;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import network.crypta.client.FECCodec;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.async.PersistentJobRunner.CheckpointLock;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.support.MemoryLimitedChunk;
import network.crypta.support.MemoryLimitedJob;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Storage and decode/encode coordinator for a single cross‑segment of a split file.
 *
 * <p>A cross‑segment runs in parallel with the main segment layout and participates in an
 * interlaced Reed–Solomon scheme. The goal is to recover or recompute blocks that are missing or
 * invalid in their primary segments by combining data and "cross‑check" blocks from other segments.
 * Each cross‑segment contains a fixed number of data blocks and a smaller fixed number of check
 * blocks (typically three). This class tracks which blocks are available, reads and validates them
 * against their expected keys, and invokes the configured forward error correction ({@link
 * network.crypta.client.FECCodec}) to decode missing data or to encode missing check blocks.
 *
 * <p>This type encapsulates the life cycle of a cross‑segment decode attempt. It reacts to
 * notifications that relevant blocks have arrived, defers expensive work to memory‑limited jobs,
 * and ensures that completion or failure is signaled exactly once to the owning {@link
 * SplitFileFetcherStorage}. Synchronization guards state transitions such as "decoding",
 * "canceled", and "succeeded" so that concurrent arrivals do not trigger duplicate work.
 *
 * <ul>
 *   <li>Tracks membership: which segment and block number provide each cross‑segment block.
 *   <li>Reads and validates blocks from the disk with defensive handling of I/O failures.
 *   <li>Performs FEC decode/encode and reports recovered blocks back to their segments.
 *   <li>Bounds memory via {@link network.crypta.support.MemoryLimitedJobRunner} jobs.
 * </ul>
 *
 * @see SplitFileFetcherStorage
 * @see SplitFileFetcherSegmentStorage
 * @see network.crypta.client.FECCodec
 */
public final class SplitFileFetcherCrossSegmentStorage {
  private static final Logger LOG =
      LoggerFactory.getLogger(SplitFileFetcherCrossSegmentStorage.class);

  /**
   * The zero‑based cross‑segment ordinal within the parent fetch operation. The value is constant
   * for the lifetime of this instance and can be used for logging or UI purposes; it does not
   * change decoding behavior.
   */
  public final int crossSegmentNumber;

  /**
   * Owning storage that coordinates all segments for the overall split‑file request. The parent is
   * used to get priorities, schedule persistent jobs, and report success or fatal errors. The
   * reference remains valid until the fetch completes or is canceled.
   */
  public final SplitFileFetcherStorage parent;

  /** Segment for each block */
  private final SplitFileFetcherSegmentStorage[] segments;

  /** Block number within the segment for each block */
  private final int[] blockNumbers;

  /**
   * Whether each block in the cross-segment has been found. Kept up to date when blocks are found
   * in the other segments. However, as in a normal segment, these may not be 100% accurate!
   */
  private final boolean[] blocksFound;

  /** Number of data blocks chosen from the various segments. */
  final int dataBlockCount;

  /** Number of check blocks chosen from the various segments. Typically, 3. */
  final int crossCheckBlockCount;

  final int totalBlocks;
  private int totalFound;

  /** If true, we are currently decoding */
  private boolean tryDecode;

  /** True if the request has been terminated for some reason. */
  private boolean cancelled;

  /**
   * If true, the segment has completed. Once a segment decoding starts, finished must not be set
   * until it exits.
   */
  private boolean succeeded;

  private final FECCodec codec;

  /** Used in assigning blocks */
  private int counter;

  SplitFileFetcherCrossSegmentStorage(
      int segNo,
      int blocksPerSegment,
      int crossCheckBlocks,
      SplitFileFetcherStorage parent,
      FECCodec codec) {
    this.crossSegmentNumber = segNo;
    this.parent = parent;
    this.dataBlockCount = blocksPerSegment;
    this.crossCheckBlockCount = crossCheckBlocks;
    totalBlocks = dataBlockCount + crossCheckBlocks;
    this.codec = codec;
    segments = new SplitFileFetcherSegmentStorage[totalBlocks];
    blockNumbers = new int[totalBlocks];
    blocksFound = new boolean[totalBlocks];
  }

  /**
   * Notify this cross‑segment that a constituent segment reports a relevant block has been fetched.
   *
   * <p>The method marks the corresponding cross‑segment position as available, updates internal
   * counters, and, when enough blocks are present to attempt recovery, schedules a bounded
   * decode/encode job. Calls are idempotent per block: reporting the same block more than once has
   * no further effect. If the request is canceled or has already succeeded, the call is ignored.
   *
   * @param segment the originating {@link SplitFileFetcherSegmentStorage}; must match the segment
   *     recorded for this cross‑segment position and must not be {@code null}
   * @param blockNo the block number within {@code segment} that became available; non‑negative and
   *     within the segment’s declared range
   */
  public void onFetchedRelevantBlock(SplitFileFetcherSegmentStorage segment, int blockNo) {
    short priorityClass = parent.getPriorityClass();
    synchronized (this) {
      boolean found = false;
      for (int i = 0; i < segments.length; i++) {
        if (segments[i] == segment && blockNumbers[i] == blockNo) {
          found = true;
          if (blocksFound[i]) {
            // Already handled, don't loop.
            return;
          }
          blocksFound[i] = true;
          totalFound++;
        }
      }
      if (tryDecode || succeeded || cancelled) return;
      if (!found) {
        LOG.warn("Block {} on {} not wanted by {}", blockNo, segment, this);
        return;
      }
      if (totalFound < dataBlockCount) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Not decoding {} : found {} blocks of {} (total {})",
              this,
              totalFound,
              dataBlockCount,
              segments.length);
        return;
      }
      tryDecodeOrEncode(priorityClass);
    }
  }

  private synchronized void tryDecodeOrEncode(final short prio) {
    if (succeeded) return;
    if (tryDecode) return;
    if (cancelled) return;
    long limit =
        (long) totalBlocks * CHKBlock.DATA_LENGTH
            + Math.max(
                parent.fecCodec.maxMemoryOverheadDecode(dataBlockCount, crossCheckBlockCount),
                parent.fecCodec.maxMemoryOverheadEncode(dataBlockCount, crossCheckBlockCount));
    parent.memoryLimitedJobRunner.queueJob(
        new MemoryLimitedJob(limit) {

          @Override
          public int getPriority() {
            return prio;
          }

          @Override
          public boolean start(MemoryLimitedChunk chunk) {
            boolean shutdown = false;
            CheckpointLock lock = null;
            try {
              lock = parent.jobRunner.lock();
              innerDecode();
            } catch (PersistenceDisabledException _) {
              shutdown = true;
            } finally {
              chunk.release();
              try {
                if (!shutdown) {
                  // We do want to call the callback even if we threw something, because we
                  // may be waiting to cancel. However, we DON'T call it if we are shutting down.
                  synchronized (SplitFileFetcherCrossSegmentStorage.this) {
                    tryDecode = false;
                  }
                  parent.finishedEncoding(SplitFileFetcherCrossSegmentStorage.this);
                }
              } finally {
                // Callback is part of the persistent job, unlock *after* calling it.
                if (lock != null) lock.unlock(false, MemoryLimitedJobRunner.THREAD_PRIORITY);
              }
            }
            return true;
          }
        });
    tryDecode = true;
  }

  /**
   * Attempt FEC processing for this cross‑segment.
   *
   * <p>The method reads all data and check blocks that belong to the cross‑segment, validates them
   * against their expected keys, and invokes {@link FECCodec} to decode missing data or to encode
   * missing check blocks. Newly recovered blocks are verified and, if valid, reported back to their
   * owning segments. If any disk I/O error is encountered while reading, the failure is reported to
   * the parent asynchronously and processing exits early.
   */
  private void innerDecode() {
    if (LOG.isDebugEnabled()) LOG.debug("Trying to decode {} for {}", this, parent);
    if (isFinishedOrCancelled()) return;

    // readAllBlocks does most of the housekeeping for us, see below...
    byte[][] dataBlocks = readBlocks(false);
    byte[][] checkBlocks = readBlocks(true);

    // If a disk error occurred while reading, readBlocks() returns null and
    // failDiskOffThread() has been scheduled. Exit early to avoid crashing.
    if (dataBlocks == null || checkBlocks == null) {
      return;
    }

    // Original status.
    boolean[] dataBlocksFound = wasNonNullFill(dataBlocks);
    boolean[] checkBlocksFound = wasNonNullFill(checkBlocks);

    int realTotalDataBlocks = count(dataBlocksFound);
    int realTotalCrossCheckBlocks = count(checkBlocksFound);
    int realTotalFound = realTotalDataBlocks + realTotalCrossCheckBlocks;

    if (realTotalFound < dataBlockCount) {
      // Not finished yet.
      return;
    }

    boolean decoded = false;
    boolean encoded = false;

    if (realTotalDataBlocks < dataBlockCount) {
      decodeMissingDataBlocks(dataBlocks, checkBlocks, dataBlocksFound, checkBlocksFound);
    }

    if (realTotalCrossCheckBlocks < crossCheckBlockCount) {
      encodeMissingCheckBlocks(dataBlocks, checkBlocks, checkBlocksFound);
    }

    synchronized (this) {
      succeeded = true;
    }

    if (LOG.isDebugEnabled())
      LOG.debug("Completed a cross-segment: decoded={} encoded={}", decoded, encoded);
  }

  private boolean isFinishedOrCancelled() {
    synchronized (this) {
      return succeeded || cancelled;
    }
  }

  private void decodeMissingDataBlocks(
      byte[][] dataBlocks,
      byte[][] checkBlocks,
      boolean[] dataBlocksFound,
      boolean[] checkBlocksFound) {
    // Decode data blocks and validate newly recovered ones.
    codec.decode(dataBlocks, checkBlocks, dataBlocksFound, checkBlocksFound, CHKBlock.DATA_LENGTH);
    for (int i = 0; i < dataBlockCount; i++) {
      if (!dataBlocksFound[i]) {
        checkDecodedBlock(i, dataBlocks[i]);
        dataBlocksFound[i] = true;
      }
    }
  }

  private void encodeMissingCheckBlocks(
      byte[][] dataBlocks, byte[][] checkBlocks, boolean[] checkBlocksFound) {
    // Recompute missing check blocks and validate them.
    codec.encode(dataBlocks, checkBlocks, checkBlocksFound, CHKBlock.DATA_LENGTH);
    for (int i = 0; i < crossCheckBlockCount; i++) {
      if (!checkBlocksFound[i]) {
        checkDecodedBlock(i + dataBlockCount, checkBlocks[i]);
      }
    }
  }

  private void checkDecodedBlock(int i, byte[] data) {
    ClientCHK key = getKey(i);
    if (key == null) {
      LOG.error("Key not found");
      failOffThread(new FetchException(FetchExceptionMode.INTERNAL_ERROR, "Key not found"));
      return;
    }
    ClientCHKBlock block = encodeBlock(key, data);
    String decoded = i >= dataBlockCount ? "Encoded" : "Decoded";
    if (block == null || !key.getNodeCHK().equals(block.getKey())) {
      LOG.error("{} cross-segment block {} failed!", decoded, i);
      failOffThread(
          new FetchException(
              FetchExceptionMode.SPLITFILE_DECODE_ERROR,
              decoded + " cross-segment block does not match expected key"));
    } else {
      reportBlockToSegmentOffThread(i, key, block, data);
    }
  }

  private ClientCHKBlock encodeBlock(ClientCHK key, byte[] data) {
    try {
      return ClientCHKBlock.encodeSplitfileBlock(
          data, key.getCryptoKey(), key.getCryptoAlgorithm());
    } catch (CHKEncodeException _) {
      return null;
    }
  }

  private void reportBlockToSegmentOffThread(
      final int blockNo, final ClientCHK key, final ClientCHKBlock block, final byte[] data) {
    parent.jobRunner.queueNormalOrDrop(
        _ -> {
          try {
            // Note: consider adding a segment API to avoid re-decoding and reduce CPU usage.
            SplitFileSegmentKeys keys = segments[blockNo].getSegmentKeys();
            boolean success =
                segments[blockNo].innerOnGotKey(
                    key.getNodeCHK(), block, keys, blockNumbers[blockNo], data);
            if (success) {
              if (LOG.isDebugEnabled()) LOG.debug("Successfully decoded cross-segment block");
            } else {
              // Not really a big deal, but potentially interesting...
              LOG.warn("Decoded cross-segment block but not wanted by segment");
            }
          } catch (IOException e) {
            parent.failOnDiskError(e);
            return true;
          }
          return false;
        });
  }

  private void failOffThread(final FetchException e) {
    parent.jobRunner.queueNormalOrDrop(
        _ -> {
          parent.fail(e);
          return true;
        });
  }

  private void failDiskOffThread(final IOException e) {
    parent.jobRunner.queueNormalOrDrop(
        _ -> {
          parent.failOnDiskError(e);
          return true;
        });
  }

  private ClientCHK getKey(int i) {
    return segments[i].getKey(blockNumbers[i]);
  }

  private static boolean[] wasNonNullFill(byte[][] blocks) {
    boolean[] nonNulls = new boolean[blocks.length];
    for (int i = 0; i < blocks.length; i++) {
      // Treat null or empty arrays as absent; provide a zero-filled buffer for codec.
      if (blocks[i] == null || blocks[i].length == 0) {
        blocks[i] = new byte[CHKBlock.DATA_LENGTH];
      } else {
        nonNulls[i] = true;
      }
    }
    return nonNulls;
  }

  /**
   * Read all blocks from the referenced segments and validate their contents against expected keys.
   *
   * @param checkBlocks when {@code false}, reads data blocks; when {@code true}, reads check
   *     blocks. The codec expects separate arrays for data and checks.
   * @return a dense array ordered for the codec. Elements are either a valid block or {@code null}
   *     when invalid or not yet fetched. Returns {@code null} on disk I/O failure after notifying
   *     the parent via the disk‑failure path.
   */
  @SuppressWarnings("java:S1168")
  private byte[][] readBlocks(boolean checkBlocks) {
    int start = checkBlocks ? dataBlockCount : 0;
    int end = checkBlocks ? totalBlocks : dataBlockCount;
    byte[][] blocks = new byte[end - start][];
    for (int i = start; i < end; i++) {
      try {
        byte[] block = segments[i].checkAndGetBlockData(blockNumbers[i]);
        byte[] normalizedBlock = normalizeBlock(block);
        blocks[i - start] = normalizedBlock;
        updateBlockFound(i, normalizedBlock != null);
      } catch (IOException e) {
        failDiskOffThread(e);
        return null;
      }
    }
    return blocks;
  }

  /**
   * Normalize a raw block by treating {@code null} or empty data as missing.
   *
   * @param block raw block data from disk
   * @return the original block when valid, or {@code null} when missing/invalid
   */
  private static byte[] normalizeBlock(byte[] block) {
    return (block == null || block.length == 0) ? null : block;
  }

  /**
   * Update the found tracking and counters for a single block index.
   *
   * @param blockIndex the absolute block index in this cross-segment
   * @param found {@code true} if the block is present and valid
   */
  private void updateBlockFound(int blockIndex, boolean found) {
    synchronized (this) {
      boolean wasFound = blocksFound[blockIndex];
      if (wasFound != found) {
        totalFound += found ? 1 : -1;
        blocksFound[blockIndex] = found;
      }
    }
  }

  private static int count(boolean[] array) {
    int total = 0;
    for (boolean b : array) if (b) total++;
    return total;
  }

  /**
   * Associate one segment/block pair with the next cross‑segment position.
   *
   * <p>Called during construction to define the mapping between cross‑segment indices and the
   * underlying segments. Each call appends a mapping; callers must make exactly {@code
   * dataBlockCount + crossCheckBlockCount} calls to fully define the cross‑segment.
   *
   * @param seg the contributing segment that holds the referenced block; must not be {@code null}
   * @param blockNum the block number within {@code seg}; must be within that segment’s range
   */
  public void addDataBlock(SplitFileFetcherSegmentStorage seg, int blockNum) {
    segments[counter] = seg;
    blockNumbers[counter] = blockNum;
    counter++;
  }

  /**
   * Report whether a decode/encode job is currently active for this cross‑segment.
   *
   * @return {@code true} while a memory‑limited job is queued or running to decode/encode; returns
   *     {@code false} otherwise. The value may change concurrently.
   */
  public synchronized boolean isDecoding() {
    return tryDecode;
  }

  /**
   * Write the fixed cross‑segment mapping to a stream.
   *
   * <p>The format consists of two integers (data block count, check block count) followed by, for
   * each cross‑segment position, the segment number and the block number within that segment. The
   * output is enough to reconstruct the mapping using the stream constructor.
   *
   * @param dos destination stream; the caller owns the stream’s lifetime and buffering policy and
   *     must not be {@code null}
   * @throws IOException if the underlying stream cannot be written or errors occur while writing
   */
  public void writeFixedMetadata(DataOutputStream dos) throws IOException {
    dos.writeInt(dataBlockCount);
    dos.writeInt(crossCheckBlockCount);
    for (int i = 0; i < totalBlocks; i++) {
      dos.writeInt(segments[i].segNo);
      dos.writeInt(blockNumbers[i]);
    }
  }

  /**
   * Reconstruct a cross‑segment from its serialized mapping.
   *
   * <p>This constructor reads the fixed metadata produced by {@link
   * #writeFixedMetadata(DataOutputStream)} and re‑establishes the mapping between cross‑segment
   * indices and their contributing segments/blocks. It also registers callbacks so that the
   * cross‑segment is notified when blocks become available.
   *
   * @param parent owning fetcher/storage that supplies segments and job runners; must not be {@code
   *     null}
   * @param segNo zero‑based cross‑segment ordinal within the parent; used for identification only
   * @param dis source stream positioned at the beginning of the cross‑segment mapping; must not be
   *     {@code null}
   * @throws IOException if reading from {@code dis} fails
   * @throws StorageFormatException if any index in the stream is out of bounds or inconsistent with
   *     the parent’s segments
   */
  public SplitFileFetcherCrossSegmentStorage(
      SplitFileFetcherStorage parent, int segNo, DataInputStream dis)
      throws IOException, StorageFormatException {
    this.parent = parent;
    this.crossSegmentNumber = segNo;
    this.codec = parent.fecCodec;
    this.dataBlockCount = dis.readInt();
    this.crossCheckBlockCount = dis.readInt();
    this.totalBlocks = dataBlockCount + crossCheckBlockCount;
    blocksFound = new boolean[totalBlocks];
    segments = new SplitFileFetcherSegmentStorage[totalBlocks];
    blockNumbers = new int[totalBlocks];
    for (int i = 0; i < totalBlocks; i++) {
      int readSeg = dis.readInt();
      if (readSeg < 0 || readSeg >= parent.segments.length)
        throw new StorageFormatException("Invalid segment number " + readSeg);
      SplitFileFetcherSegmentStorage segment = parent.segments[readSeg];
      this.segments[i] = segment;
      int blockNo = dis.readInt();
      if (blockNo < 0 || blockNo >= segment.totalBlocks())
        throw new StorageFormatException(
            "Invalid block number " + blockNo + " for segment " + segment.segNo);
      this.blockNumbers[i] = blockNo;
      segment.resumeCallback(blockNo, this);
    }
  }

  /**
   * Scan referenced segments and mark blocks already present on the disk.
   *
   * <p>Invoked after the parent has read segment metadata, this method initializes internal
   * availability counters from the current on‑disk state. It performs no locking; callers typically
   * use it during construction before scheduling any decoding attempts.
   */
  public synchronized void checkBlocks() {
    for (int i = 0; i < totalBlocks; i++) {
      if (segments[i].hasBlock(blockNumbers[i])) {
        blocksFound[i] = true;
        totalFound++;
      }
    }
  }

  /**
   * Check for sufficient blocks and schedule a decode/encode attempt if possible.
   *
   * <p>If the cross‑segment has not yet succeeded and enough blocks are available to start, queues
   * a memory‑limited job that performs the FEC work. The method returns immediately; completion is
   * signaled asynchronously via the parent.
   */
  public void restart() {
    synchronized (this) {
      if (succeeded) return;
    }
    short priorityClass = parent.getPriorityClass();
    synchronized (this) {
      if (totalBlocks < dataBlockCount) return;
      tryDecodeOrEncode(priorityClass);
    }
  }

  /**
   * Cancel further processing and mark the cross‑segment as finished.
   *
   * <p>If a decode/encode job is in progress, the completion callback will not be invoked until the
   * job exits; otherwise the method schedules the usual completion notification on the parent.
   * After cancellation, further notifications are ignored.
   */
  public void cancel() {
    synchronized (this) {
      cancelled = true;
      if (tryDecode) return;
      succeeded = true;
    }
    parent.finishedEncoding(this);
  }

  @SuppressWarnings("unused")
  int[] getSegmentNumbers() {
    int[] ret = new int[totalBlocks];
    for (int i = 0; i < totalBlocks; i++) ret[i] = segments[i].segNo;
    return ret;
  }

  int[] getBlockNumbers() {
    return blockNumbers.clone();
  }
}

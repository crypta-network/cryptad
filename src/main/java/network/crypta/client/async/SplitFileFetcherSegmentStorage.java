package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.ref.SoftReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.async.PersistentJobRunner.CheckpointLock;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKDecodeException;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.support.MemoryLimitedChunk;
import network.crypta.support.MemoryLimitedJob;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.api.LockableRandomAccessBuffer.RAFLock;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Stores and decodes a single splitfile segment both in memory and on disk.
 *
 * <p>A segment aggregates a fixed number of data and check blocks. It is responsible for tracking
 * which blocks were fetched, verifying integrity, performing forward error correction (FEC) decode
 * when enough inputs are available, and writing validated data to the parent storage. On-disk
 * metadata may be stale or corrupted; this implementation defensively revalidates information and
 * opportunistically corrects inconsistencies as blocks arrive or are decoded. As a result, the
 * component is resilient to partial disk corruption and interrupted runs, although it cannot
 * guarantee recovery from arbitrary damage.
 *
 * <p>Typical usage follows this pattern: construct the segment (either from parameters or from
 * persisted metadata), supply blocks via {@link #onGotKey(NodeCHK, CHKBlock)}, let the segment
 * schedule a decoding when enough inputs are present ({@link #tryStartDecode()}), and observe
 * completion via {@link #hasSucceeded()} and {@link #isFinished()}. The segment pushes status
 * updates back to its parent {@link SplitFileFetcherStorage} and can notify cross-segment helpers
 * when relevant blocks arrive.
 *
 * <p>Concurrency: this class synchronizes its mutable state internally. Long-running or
 * memory-heavy operations are executed through a {@link MemoryLimitedJobRunner} to bound memory
 * usage. Callers should not assume reentrancy. The instance is mutable until the segment finishes
 * or fails; after that the public getters are stable.
 *
 * <ul>
 *   <li>Responsibilities: persist/read metadata, track retries, validate keys, run FEC, and write
 *       verified data.
 *   <li>Notable behaviors: tolerates inconsistent on-disk state and self-heals where possible.
 *   <li>Trade-offs: prefers correctness and determinism over eager throughput when metadata is
 *       suspect.
 * </ul>
 *
 * @see SplitFileFetcherStorage
 */
public class SplitFileFetcherSegmentStorage {
  private static final Logger LOG = LoggerFactory.getLogger(SplitFileFetcherSegmentStorage.class);

  // Set this to "false" to turn off checking the CHKs on blocks decoded (and encoded) via FEC.
  // Generally, it is a good idea to have consistent behavior regardless of what order we fetched
  // the blocks in or whether binary blobs are enabled. This has caught nasty bugs in the past,
  // although now we have hashes at file level.
  private static final boolean FORCE_CHECK_FEC_KEYS = true;

  /** The segment number within the splitfile */
  final int segNo;

  /** Offset to the segment's block data. Initially we fill this up. */
  final long segmentBlockDataOffset;

  /**
   * Offset to the segment's cross-check block data. This may be kept separately if we are going to
   * complete the fetch via truncation, otherwise it's at the end of the segment data.
   */
  final long segmentCrossCheckBlockDataOffset;

  /** Offset to the segment's status metadata storage. */
  final long segmentStatusOffset;

  /**
   * The length of the segment status for purposes of locating it on disk may be larger than
   * segmentStatusLength.
   */
  final int segmentStatusPaddedLength;

  /** Offset to the segment's key list */
  final long segmentKeyListOffset;

  /** Length of the segment key list */
  final int segmentKeyListLength;

  /** The splitfile */
  final SplitFileFetcherStorage parent;

  /**
   * Count of data blocks (actual data divided up into CHKs, though the last one will be padded).
   * Numbered 0..dataBlocks-1.
   */
  public final int dataBlocks;

  /**
   * Count of cross-segment check blocks. These occur only in larger splitfiles and count as data
   * blocks for segment-level FEC, but they also count as check blocks for cross-segment level FEC.
   * Generally between 0 and 3. Numbered dataBlocks..dataBlocks+crossSegmentCheckBlocks-1
   */
  public final int crossSegmentCheckBlocks;

  /**
   * Count of check blocks (generated by FEC). Numbered
   * dataBlocks+crossSegmentCheckBlocks..dataBlocks+crossSegmentCheckBlocks+checkBlocks-1
   */
  public final int checkBlocks;

  /** Keeps track of how many times we've tried each block, which blocks we have downloaded etc. */
  private final SplitFileFetcherSegmentBlockChooser blockChooser;

  /**
   * What is the order of the blocks on the disk? Should be kept consistent with blocksFound! Is
   * read from disk on startup and may be inaccurate, checked on FEC decoding. Elements: -1 = not
   * fetched yet.
   */
  private final int[] blocksFetched;

  /**
   * True if we have downloaded and decoded all the data blocks and cross-segment check blocks and
   * written them to their final location in the parent storage file.
   */
  private boolean succeeded;

  /**
   * True if we have not only downloaded and decoded, but also finished with encoding and queueing
   * healing blocks.
   */
  private boolean finished;

  /**
   * True if the segment has been canceled, has failed due to an internal error, etc. In which case
   * it is not interested in further blocks. Not true if it has run out of retries, in which case
   * (for cross-segment) we may still be interested in blocks.
   */
  private boolean failed;

  /** True if we've run out of retries. */
  private boolean failedRetries;

  /** True if the metadata needs writing but isn't going to be written immediately. */
  private boolean metadataDirty;

  /** True if the metadata was corrupt and we need to innerDecode(). */
  private boolean corruptMetadata;

  /**
   * The cross-segments for each data or cross-segment check block. This allows us to tell the
   * cross-segments when we may have data to decode. The array is null if there are no
   * cross-segments, and the elements are null if there is no associated cross-segment.
   */
  private final SplitFileFetcherCrossSegmentStorage[] crossSegmentsByBlock;

  private SoftReference<SplitFileSegmentKeys> keysCache;
  private boolean tryDecode;
  private int crossDataBlocksAllocated;
  private int crossCheckBlocksAllocated;

  /** Number of blocks we've given up on. */
  private int failedBlocks;

  /** Parameter bundle for constructing a new segment from parameters. */
  public static final class InitParams {
    SplitFileFetcherStorage parent;
    int segNumber;
    int dataBlocks;
    int checkBlocks;
    int crossCheckBlocks;
    long segmentDataOffset;
    long segmentCrossCheckDataOffset; // -1 to place after data
    long segmentKeysOffset;
    long segmentStatusOffset;
    boolean writeRetries;
    SplitFileSegmentKeys keys;
    KeysFetchingLocally keysFetching;
  }

  /** Parameter bundle for constructing a segment from saved metadata. */
  public static final class LoadParams {
    SplitFileFetcherStorage parent;
    DataInputStream dis;
    int segNo;
    boolean writeRetries;
    long segmentDataOffset;
    long segmentCrossCheckDataOffset; // -1 to place after data
    long segmentKeysOffset;
    long segmentStatusOffset;
    KeysFetchingLocally keysFetching;
  }

  /**
   * Construct a segment.
   *
   * @param p Initialization parameters for the segment.
   */
  public SplitFileFetcherSegmentStorage(InitParams p) {
    this.parent = p.parent;
    this.segNo = p.segNumber;
    this.dataBlocks = p.dataBlocks;
    this.checkBlocks = p.checkBlocks;
    this.crossSegmentCheckBlocks = p.crossCheckBlocks;
    int total = p.dataBlocks + p.checkBlocks + crossSegmentCheckBlocks;
    boolean ignoreLastBlock =
        (segNo == parent.segments.length - 1 && parent.lastBlockMightNotBePadded());
    this.blockChooser =
        new SplitFileFetcherSegmentBlockChooser(
            total,
            parent.random,
            parent.maxRetries,
            parent.cooldownTries,
            parent.cooldownLength,
            new SplitFileFetcherSegmentBlockChooserParams(
                this, p.keysFetching, ignoreLastBlock ? p.dataBlocks - 1 : -1));
    int minFetched = blocksForDecode();
    if (this.crossSegmentCheckBlocks != 0)
      crossSegmentsByBlock = new SplitFileFetcherCrossSegmentStorage[minFetched];
    else crossSegmentsByBlock = null;
    blocksFetched = new int[minFetched];
    Arrays.fill(blocksFetched, -1);
    segmentStatusPaddedLength =
        paddedStoredSegmentStatusLength(
            p.dataBlocks,
            p.checkBlocks,
            p.crossCheckBlocks,
            p.writeRetries,
            parent.checksumLength,
            parent.persistent);
    segmentKeyListLength =
        storedKeysLength(
            blocksForDecode(),
            p.checkBlocks,
            parent.splitfileSingleCryptoKey != null,
            parent.checksumLength);
    this.segmentBlockDataOffset = p.segmentDataOffset;
    long sccdo = p.segmentCrossCheckDataOffset;
    if (sccdo == -1) {
      sccdo = segmentBlockDataOffset + (long) p.dataBlocks * CHKBlock.DATA_LENGTH;
    }
    this.segmentCrossCheckBlockDataOffset = sccdo;
    this.segmentKeyListOffset = p.segmentKeysOffset;
    this.segmentStatusOffset = p.segmentStatusOffset;
    // This must be passed in here, or we will read the uninitialised keys!
    keysCache = new SoftReference<>(p.keys);
  }

  /**
   * Construct from persisted metadata.
   *
   * <p>Uses the {@link DataInputStream} in {@code p} to read static settings (the block counts). It
   * does not use the RAF to read variable state such as fetched-block order or retries; callers
   * must invoke {@link #readMetadata()} and read the keys separately.
   *
   * @param p Load parameters. The {@code dis} stream contains the statically persisted attributes
   *     for this segment (block counts); dynamic status and keys are read separately from the
   *     parent random-access storage.
   * @throws IOException if the stream cannot be read or ends prematurely while reading attributes.
   * @throws StorageFormatException if persisted values fall outside allowed ranges or otherwise
   *     violate the expected storage format.
   */
  public SplitFileFetcherSegmentStorage(LoadParams p) throws IOException, StorageFormatException {
    this.segNo = p.segNo;
    this.parent = p.parent;
    DataInputStream dis = p.dis;
    this.dataBlocks = dis.readInt();
    if (dataBlocks < 1 || dataBlocks > 256)
      throw new StorageFormatException("Bad data block count");
    this.crossSegmentCheckBlocks = dis.readInt();
    // REDFLAG one day we will support more than 256 blocks per segment?
    if (crossSegmentCheckBlocks < 0 || crossSegmentCheckBlocks > 256)
      throw new StorageFormatException("Bad cross-segment check block count");
    this.checkBlocks = dis.readInt();
    if (checkBlocks < 0 || checkBlocks > 256)
      throw new StorageFormatException("Bad check block count");
    int total = dataBlocks + checkBlocks + crossSegmentCheckBlocks;
    if (total > 256) throw new StorageFormatException("Too many blocks in segment");
    boolean ignoreLastBlock =
        (segNo == parent.segments.length - 1 && parent.lastBlockMightNotBePadded());
    blockChooser =
        new SplitFileFetcherSegmentBlockChooser(
            total,
            parent.random,
            parent.maxRetries,
            parent.cooldownTries,
            parent.cooldownLength,
            new SplitFileFetcherSegmentBlockChooserParams(
                this, p.keysFetching, ignoreLastBlock ? dataBlocks - 1 : -1));
    int minFetched = blocksForDecode();
    if (crossSegmentCheckBlocks != 0)
      crossSegmentsByBlock = new SplitFileFetcherCrossSegmentStorage[minFetched];
    else crossSegmentsByBlock = null;
    blocksFetched = new int[minFetched];
    Arrays.fill(blocksFetched, -1);
    segmentStatusPaddedLength =
        paddedStoredSegmentStatusLength(
            dataBlocks,
            checkBlocks,
            crossSegmentCheckBlocks,
            p.writeRetries,
            parent.checksumLength,
            true);
    segmentKeyListLength =
        storedKeysLength(
            blocksForDecode(),
            checkBlocks,
            parent.splitfileSingleCryptoKey != null,
            parent.checksumLength);
    keysCache = null; // Will be read later
    this.segmentBlockDataOffset = p.segmentDataOffset;
    long sccdo = p.segmentCrossCheckDataOffset;
    if (sccdo == -1) {
      sccdo = segmentBlockDataOffset + dataBlocks * ((long) CHKBlock.DATA_LENGTH);
    }
    this.segmentCrossCheckBlockDataOffset = sccdo;
    this.segmentKeyListOffset = p.segmentKeysOffset;
    this.segmentStatusOffset = p.segmentStatusOffset;
  }

  /**
   * Returns the immutable key list for this segment, loading it from disk on first access and
   * caching it for later calls.
   *
   * <p>If the on-disk key list is corrupt, the error is treated as fatal and surfaced as an {@link
   * IOException}. Callers should not retain the returned object for cross-segment reuse once the
   * parent storage is closed.
   *
   * @return a cached {@link SplitFileSegmentKeys} instance representing decryption/verification
   *     keys for data and check blocks; {@code null} only when the segment was initialized without
   *     persisted keys.
   * @throws IOException if reading the checksummed key list fails or a checksum mismatch is
   *     detected.
   */
  public SplitFileSegmentKeys getSegmentKeys() throws IOException {
    synchronized (this) {
      if (keysCache != null) {
        SplitFileSegmentKeys cached = keysCache.get();
        if (cached != null) return cached;
      }
      SplitFileSegmentKeys keys;
      try {
        keys = readSegmentKeys();
      } catch (ChecksumFailedException e) {
        LOG.error("Keys corrupted on {} !", this);
        // Treat as IOException, i.e., fatal.
        throw new IOException(e);
      }
      if (keys == null) return null;
      keysCache = new SoftReference<>(keys);
      return keys;
    }
  }

  SplitFileSegmentKeys readSegmentKeys() throws IOException, ChecksumFailedException {
    SplitFileSegmentKeys keys =
        new SplitFileSegmentKeys(
            blocksForDecode(),
            checkBlocks,
            parent.splitfileSingleCryptoKey,
            parent.splitfileSingleCryptoAlgorithm);
    byte[] buf =
        new byte
            [SplitFileSegmentKeys.storedKeysLength(
                blocksForDecode(), checkBlocks, parent.splitfileSingleCryptoKey != null)];
    parent.preadChecksummed(segmentKeyListOffset, buf, 0, buf.length);
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(buf));
    keys.readKeys(dis, false);
    keys.readKeys(dis, true);
    return keys;
  }

  /**
   * Write the status metadata to disk, after a series of updates.
   *
   * <p>This method batches frequent in-memory changes and persists them atomically under a
   * checksum, reducing I/O churn. It may be a no-op if nothing has changed since the last writing.
   */
  public void writeMetadata() {
    writeMetadata(true);
  }

  /**
   * Write the status metadata to disk, after a series of updates.
   *
   * @param force when {@code true}, writes immediately; when {@code false}, the writing may be
   *     deferred and coalesced by the parent to minimize I/O while preserving correctness.
   */
  public void writeMetadata(boolean force) {
    innerWriteMetadata(force);
  }

  /**
   * Read all the blocks, encode them according to their supposed keys, and check that they are in
   * fact the blocks that they should be. If the metadata is inaccurate, update it and
   * writeMetadata(). If we have enough blocks to decode, and we don't have all the blocks, then
   * schedule a decoding on the FEC thread.
   *
   * @return True if we scheduled a decoding or are already finished. False if we do not have enough
   *     blocks to decode and need to fetch more blocks.
   */
  @SuppressWarnings("UnusedReturnValue")
  public boolean tryStartDecode() {
    synchronized (this) {
      if (succeeded || failed || finished) return false;
      if (!corruptMetadata && blockChooser.successCount() < blocksForDecode()) return false;
      if (tryDecode) return true;
      tryDecode = true;
    }
    long limit =
        (long) totalBlocks() * CHKBlock.DATA_LENGTH
            + Math.max(
                parent.fecCodec.maxMemoryOverheadDecode(blocksForDecode(), checkBlocks),
                parent.fecCodec.maxMemoryOverheadEncode(blocksForDecode(), checkBlocks));
    final int prio = parent.getPriorityClass();
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
            } catch (IOException e) {
              LOG.error("event=decode_disk_error segment={} error={}", this, e, e);
              parent.failOnDiskError(e);
            } catch (PersistenceDisabledException _) {
              // Shutting down.
              // We don't call the callback here, so we don't care.
              shutdown = true;
            } catch (Exception e) {
              LOG.error("event=decode_internal_error segment={} error={}", this, e, e);
              parent.fail(new FetchException(FetchExceptionMode.INTERNAL_ERROR, e));
            } finally {
              chunk.release();
              synchronized (SplitFileFetcherSegmentStorage.this) {
                tryDecode = false;
              }
              try {
                // We may not have completed, but we HAVE finished.
                // Need to tell the parent, so it can do something about it.
                // In particular, if we fail, we may need to complete cancellation, and we
                // can't do that until both tryDecode=false and the parent gets the callback.
                if (!shutdown) parent.finishedEncoding(SplitFileFetcherSegmentStorage.this);
              } finally {
                if (lock != null) lock.unlock(false, MemoryLimitedJobRunner.THREAD_PRIORITY);
              }
            }
            return true;
          }
        });
    return true;
  }

  /**
   * Attempt FEC decoding. Check blocks before decoding in case there is disk corruption. Check the
   * new decoded blocks afterward to ensure reproducible behavior.
   */
  private void innerDecode() throws IOException {
    if (LOG.isDebugEnabled()) LOG.debug("Trying to decode {} for {}", this, parent);
    if (shouldAbortDecode()) return;
    int totalBlocks = totalBlocks();
    byte[][] allBlocks = readAllBlocks();
    SplitFileSegmentKeys keys = getSegmentKeys();
    if (keys == null) return;
    BlocksBuildResult build = buildBlockCandidates(totalBlocks, allBlocks);
    if (build.fetchedCount() < blocksForDecode()) {
      handleInsufficientBlocksAndReturn();
      return;
    }
    DecodePrep prep = prepareDecodeArrays(build.maybeBlocks(), keys);
    if (prep.validBlocks < blocksForDecode()) {
      handleInsufficientBlocksAndReturn();
      return;
    }
    decodeIfNeeded(
        prep.validDataBlocks,
        prep.dataBlocks,
        prep.checkBlocks,
        prep.dataBlocksPresent,
        prep.checkBlocksPresent);
    boolean capturingBinaryBlob = parent.fetcher.wantBinaryBlob();
    boolean checkDecodedKeys = FORCE_CHECK_FEC_KEYS || capturingBinaryBlob;
    if (checkDecodedKeys) {
      checkDecodedDataBlocks(prep.dataBlocks, prep.dataBlocksPresent, keys, capturingBinaryBlob);
    }
    writeAllDataBlocks(prep.dataBlocks);
    if (!checkDecodedKeys) parent.finishedSuccess(this);
    triggerAllCrossSegmentCallbacks();
    parent.fecCodec.encode(
        prep.dataBlocks, prep.checkBlocks, prep.checkBlocksPresent, CHKBlock.DATA_LENGTH);
    if (checkDecodedKeys) {
      if (!checkEncodedDataBlocks(
          prep.checkBlocks, prep.checkBlocksPresent, keys, capturingBinaryBlob)) {
        synchronized (this) {
          finished = true;
        }
        parent.fail(
            new FetchException(
                FetchExceptionMode.SPLITFILE_DECODE_ERROR, "Encoded blocks do not match metadata"));
        return;
      }
      parent.finishedSuccess(this);
    }
    queueHeal(prep.dataBlocks, prep.checkBlocks, prep.dataBlocksPresent, prep.checkBlocksPresent);
    writeMetadata();
    synchronized (this) {
      corruptMetadata = false;
      finished = true;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Finished decoding {} for {}", this, parent);
  }

  private boolean shouldAbortDecode() {
    boolean fail;
    synchronized (this) {
      if (finished) return true;
      fail = succeeded || failed;
      if (fail) finished = true;
    }
    return fail;
  }

  private static final class SplitFileFetcherBlock {
    final byte[] buf;
    final int blockNumber;
    final int slot;

    SplitFileFetcherBlock(byte[] buf, int blockNumber, int slot) {
      this.buf = buf;
      this.blockNumber = blockNumber;
      this.slot = slot;
    }
  }

  private record BlocksBuildResult(List<SplitFileFetcherBlock> maybeBlocks, int fetchedCount) {}

  private BlocksBuildResult buildBlockCandidates(int totalBlocks, byte[][] allBlocks) {
    ArrayList<SplitFileFetcherBlock> maybeBlocks = new ArrayList<>();
    int fetchedCount = 0;
    synchronized (this) {
      boolean[] used = new boolean[totalBlocks];
      for (short i = 0; i < blocksFetched.length; i++) {
        if (blocksFetched[i] < 0 || blocksFetched[i] > totalBlocks) {
          LOG.warn(
              "Inconsistency decoding splitfile: slot {} has bogus block number {}",
              i,
              blocksFetched[i]);
          if (blocksFetched[i] != -1) blocksFetched[i] = -1;
          maybeBlocks.add(new SplitFileFetcherBlock(allBlocks[i], (short) -1, i));
        } else if (used[blocksFetched[i]]) {
          LOG.warn(
              "Inconsistency decoding splitfile: slot {} has duplicate block number {}",
              i,
              blocksFetched[i]);
          blocksFetched[i] = -1;
        } else {
          if (LOG.isDebugEnabled()) LOG.debug("Found block {} in slot {}", blocksFetched[i], i);
          maybeBlocks.add(new SplitFileFetcherBlock(allBlocks[i], blocksFetched[i], i));
          used[blocksFetched[i]] = true;
          fetchedCount++;
        }
      }
      if (fetchedCount < blocksForDecode()) {
        int oldBlocksFetchedCount = blockChooser.successCount();
        blockChooser.replaceSuccesses(used);
        if (blockChooser.successCount() != oldBlocksFetchedCount) {
          LOG.warn(
              "Corrected block count to {} from {}",
              blockChooser.successCount(),
              oldBlocksFetchedCount);
        }
      }
    }
    return new BlocksBuildResult(maybeBlocks, fetchedCount);
  }

  private void handleInsufficientBlocksAndReturn() {
    writeMetadata();
    synchronized (this) {
      corruptMetadata = false;
    }
    parent.restartedAfterDataCorruption();
  }

  private static final class DecodePrep {
    final byte[][] dataBlocks;
    final byte[][] checkBlocks;
    final boolean[] dataBlocksPresent;
    final boolean[] checkBlocksPresent;
    final int validBlocks;
    final int validDataBlocks;

    DecodePrep(
        byte[][] dataBlocks,
        byte[][] checkBlocks,
        boolean[] dataBlocksPresent,
        boolean[] checkBlocksPresent,
        int validBlocks,
        int validDataBlocks) {
      this.dataBlocks = dataBlocks;
      this.checkBlocks = checkBlocks;
      this.dataBlocksPresent = dataBlocksPresent;
      this.checkBlocksPresent = checkBlocksPresent;
      this.validBlocks = validBlocks;
      this.validDataBlocks = validDataBlocks;
    }
  }

  private DecodePrep prepareDecodeArrays(
      List<SplitFileFetcherBlock> maybeBlocks, SplitFileSegmentKeys keys) {
    int validBlocks = 0;
    int validDataBlocks = 0;
    byte[][] dataBlocksArr = new byte[blocksForDecode()][];
    byte[][] checkBlocksArr = new byte[this.checkBlocks][];

    for (SplitFileFetcherBlock test : maybeBlocks) {
      ProcessResult pr = processCandidateBlock(test, keys, dataBlocksArr, checkBlocksArr);
      if (pr.success()) {
        validBlocks++;
        if (pr.isData()) validDataBlocks++;
      }
    }
    maybeBlocks.clear();

    boolean[] dataBlocksPresent = new boolean[dataBlocksArr.length];
    boolean[] checkBlocksPresent = new boolean[checkBlocksArr.length];
    for (int i = 0; i < dataBlocksArr.length; i++) {
      if (dataBlocksArr[i] == null) {
        dataBlocksArr[i] = new byte[CHKBlock.DATA_LENGTH];
      } else {
        dataBlocksPresent[i] = true;
      }
    }
    for (int i = 0; i < checkBlocksArr.length; i++) {
      if (checkBlocksArr[i] == null) {
        checkBlocksArr[i] = new byte[CHKBlock.DATA_LENGTH];
      } else {
        checkBlocksPresent[i] = true;
      }
    }
    return new DecodePrep(
        dataBlocksArr,
        checkBlocksArr,
        dataBlocksPresent,
        checkBlocksPresent,
        validBlocks,
        validDataBlocks);
  }

  private record ProcessResult(boolean success, boolean isData) {}

  private ProcessResult processCandidateBlock(
      SplitFileFetcherBlock test,
      SplitFileSegmentKeys keys,
      byte[][] dataBlocks,
      byte[][] checkBlocks) {
    boolean failedLocal = false;
    int blockNumber = test.blockNumber;
    byte[] buf = test.buf;
    ClientCHK decodeKey = blockNumber == -1 ? null : keys.getKey(blockNumber, null, false);
    try {
      if (decodeKey == null) {
        // Unknown block number or missing key mapping; cannot validate without a key.
        return new ProcessResult(false, false);
      }
      ClientCHKBlock block =
          ClientCHKBlock.encodeSplitfileBlock(
              buf, decodeKey.getCryptoKey(), decodeKey.getCryptoAlgorithm());
      ClientCHK actualKey = block.getClientKey();
      if (!decodeKey.equals(actualKey)) {
        blockNumber = (short) keys.getBlockNumber(actualKey, null);
        if (blockNumber == -1) {
          LOG.error(
              "event=block_key_mismatch expectedBlock#{} slot={} segment={} key={}",
              test.blockNumber,
              test.slot,
              this,
              decodeKey);
          failedLocal = true;
          synchronized (this) {
            blockChooser.onUnSuccess(blockNumber);
            if (blocksFetched[test.slot] == test.blockNumber) {
              blocksFetched[test.slot] = (short) -1;
            }
          }
        } else {
          synchronized (this) {
            blockChooser.onUnSuccess(blockNumber);
            blocksFetched[test.slot] = blockNumber;
            this.blockChooser.onSuccess(blockNumber);
          }
        }
      }
    } catch (CHKEncodeException _) {
      LOG.error(
          "event=block_encode_failed block={} segment={} key={}", blockNumber, this, decodeKey);
      failedLocal = true;
    }
    if (!failedLocal) {
      if (blockNumber < dataBlocks.length) {
        dataBlocks[blockNumber] = buf;
        return new ProcessResult(true, blockNumber < blocksForDecode());
      } else {
        checkBlocks[blockNumber - dataBlocks.length] = buf;
        return new ProcessResult(true, false);
      }
    }
    return new ProcessResult(false, false);
  }

  private void decodeIfNeeded(
      int validDataBlocks,
      byte[][] dataBlocks,
      byte[][] checkBlocks,
      boolean[] dataBlocksPresent,
      boolean[] checkBlocksPresent) {
    if (validDataBlocks < blocksForDecode()) {
      if (LOG.isDebugEnabled()) LOG.debug("Decoding in memory for {}", this);
      parent.fecCodec.decode(
          dataBlocks, checkBlocks, dataBlocksPresent, checkBlocksPresent, CHKBlock.DATA_LENGTH);
    }
  }

  private void checkDecodedDataBlocks(
      byte[][] dataBlocks,
      boolean[] dataBlocksPresent,
      SplitFileSegmentKeys keys,
      boolean capturingBinaryBlob) {
    for (int i = 0; i < dataBlocks.length; i++) {
      if (dataBlocksPresent[i]) continue;
      ClientCHK decodeKey = keys.getKey(i, null, false);
      // Encode it to check whether the key is the same.
      ClientCHKBlock block;
      try {
        block =
            ClientCHKBlock.encodeSplitfileBlock(
                dataBlocks[i], decodeKey.getCryptoKey(), decodeKey.getCryptoAlgorithm());
        ClientCHK actualKey = block.getClientKey();
        if (!actualKey.equals(decodeKey)) {
          if (!(i == dataBlocks.length - 1
              && this.segNo == parent.segments.length - 1
              && parent.lastBlockMightNotBePadded())) {
            // Usual case.
            parent.fail(
                new FetchException(
                    FetchExceptionMode.SPLITFILE_DECODE_ERROR,
                    "Decoded block does not match expected key"));
          }
          return;
        }
        if (capturingBinaryBlob) parent.fetcher.maybeAddToBinaryBlob(block);
      } catch (CHKEncodeException _) {
        // Impossible!
        parent.fail(
            new FetchException(
                FetchExceptionMode.INTERNAL_ERROR, "Decoded block could not be encoded"));
        LOG.error("event=decoded_block_encode_failed phase=post_decode");
        return;
      }
    }
  }

  private boolean checkEncodedDataBlocks(
      byte[][] checkBlocks,
      boolean[] checkBlocksPresent,
      SplitFileSegmentKeys keys,
      boolean capturingBinaryBlob) {
    for (int i = 0; i < checkBlocks.length; i++) {
      if (checkBlocksPresent[i]) continue;
      ClientCHK decodeKey = keys.getKey(i + blocksForDecode(), null, false);
      // Encode it to check whether the key is the same.
      ClientCHKBlock block;
      try {
        block =
            ClientCHKBlock.encodeSplitfileBlock(
                checkBlocks[i], decodeKey.getCryptoKey(), decodeKey.getCryptoAlgorithm());
        ClientCHK actualKey = block.getClientKey();
        if (!actualKey.equals(decodeKey)) {
          LOG.error(
              "Splitfile check block {} does not encode to expected key for {} for {}",
              i,
              this,
              parent);
          return false;
        }
        if (capturingBinaryBlob) parent.fetcher.maybeAddToBinaryBlob(block);
      } catch (CHKEncodeException _) {
        // Impossible!
        parent.fail(
            new FetchException(
                FetchExceptionMode.INTERNAL_ERROR, "Decoded block could not be encoded"));
        LOG.error("event=check_block_encode_failed phase=post_encode");
        return false;
      }
    }
    return true;
  }

  /** queue up for healing all blocks that either failed or needed more than one try to retrieve. */
  private void queueHeal(
      byte[][] dataBlocks,
      byte[][] checkBlocks,
      boolean[] dataBlocksPresent,
      boolean[] checkBlocksPresent)
      throws IOException {
    for (int i = 0; i < dataBlocks.length; i++) {
      if (!dataBlocksPresent[i] && blockChooser.getRetries(i) != 0) {
        queueHeal(i, dataBlocks[i]);
      }
    }
    for (int i = 0; i < checkBlocks.length; i++) {
      if (!checkBlocksPresent[i] && blockChooser.getRetries(i + dataBlocks.length) != 0) {
        queueHeal(i + dataBlocks.length, checkBlocks[i]);
      }
    }
  }

  private void queueHeal(int blockNumber, byte[] data) throws IOException {
    byte[] cryptoKey;
    byte cryptoAlgorithm;
    if (parent.splitfileSingleCryptoKey != null) {
      cryptoKey = parent.splitfileSingleCryptoKey;
      cryptoAlgorithm = parent.splitfileSingleCryptoAlgorithm;
    } else {
      ClientCHK key = getSegmentKeys().getKey(blockNumber, null, false);
      cryptoKey = key.getCryptoKey();
      cryptoAlgorithm = key.getCryptoAlgorithm();
    }
    parent.fetcher.queueHeal(data, cryptoKey, cryptoAlgorithm);
  }

  private synchronized byte[][] readAllBlocks() throws IOException {
    RAFLock lock = parent.lockRAFOpen();
    try {
      // Consider using a single large byte[] if profiling indicates it's beneficial.
      byte[][] ret = new byte[blocksForDecode()][];
      for (int i = 0; i < ret.length; i++) ret[i] = readBlock(i);
      return ret;
    } finally {
      lock.unlock();
    }
  }

  private void triggerAllCrossSegmentCallbacks() {
    SplitFileFetcherCrossSegmentStorage[] crossSegmentsByBlockCopy;
    synchronized (this) {
      if (crossSegmentsByBlock == null) return;
      crossSegmentsByBlockCopy =
          Arrays.copyOf(this.crossSegmentsByBlock, this.crossSegmentsByBlock.length);
    }
    for (int i = 0; i < crossSegmentsByBlockCopy.length; i++) {
      SplitFileFetcherCrossSegmentStorage s = crossSegmentsByBlockCopy[i];
      if (s != null) s.onFetchedRelevantBlock(this, i);
    }
  }

  /** Write a full set of data blocks to the disk and update the metadata accordingly. */
  private void writeAllDataBlocks(byte[][] dataBlocks) throws IOException {
    RAFLock lock = parent.lockRAFOpen();
    try {
      synchronized (this) {
        assert (dataBlocks.length == blocksForDecode());
        for (int i = 0; i < dataBlocks.length; i++) {
          writeDownloadedBlock(i, dataBlocks[i]);
          blockChooser.onSuccess(i);
          blocksFetched[i] = (short) i;
        }
        succeeded = true;
      }
    } finally {
      lock.unlock();
    }
  }

  final int totalBlocks() {
    return dataBlocks + crossSegmentCheckBlocks + checkBlocks;
  }

  /**
   * A block has been fetched which the caller believes is one of ours. Check whether it is in fact
   * ours, and that we don't have it already. Find the key and decode it and add it to our
   * collection. If any cross-segments are waiting for this block, tell them. If we can decode, do
   * so. Can be quite involved, should be called off-thread.
   *
   * @param key the node-level key that identified the fetched block; used to map the block back to
   *     a segment-local position. Must not be {@code null}.
   * @param block the raw encrypted/encoded {@link CHKBlock} as returned by the fetch pipeline. Must
   *     contain exactly one block payload.
   * @throws IOException if the decoded payload cannot be written to the segment's storage area due
   *     to an underlying I/O error.
   * @return True if we successfully decoded a block, in which case the function will be called
   *     again. False if there was no match, if we have already fetched that block, or if various
   *     errors occurred.
   */
  public boolean onGotKey(NodeCHK key, CHKBlock block) throws IOException {
    SplitFileSegmentKeys keys = getSegmentKeys();
    if (keys == null) return false;
    int blockNumber;
    ClientCHK decodeKey;
    synchronized (this) {
      if (succeeded || failed || finished) return false;
      blockNumber = blockChooser.getBlockNumber(keys, key);
      if (blockNumber == -1) {
        if (LOG.isDebugEnabled()) LOG.debug("Block not found {}", key);
        return false;
      }
      if (blockChooser.hasSucceeded(blockNumber))
        return false; // Even if this is inaccurate, it will be corrected on a FEC attempt.
      if (tryDecode) return false;
      decodeKey = keys.getKey(blockNumber, null, false);
    }
    ClientCHKBlock decodedBlock;
    byte[] decodedData;
    try {
      decodedBlock = new ClientCHKBlock(block, decodeKey);
      decodedData = decodedBlock.memoryDecode();
    } catch (CHKVerifyException _) {
      LOG.error("event=block_verify_failed key={}", decodeKey);
      return false;
    } catch (CHKDecodeException _) {
      LOG.error("event=block_decode_failed key={}", decodeKey);
      return false;
    }
    return innerOnGotKey(key, decodedBlock, keys, blockNumber, decodedData);
  }

  /**
   * Store a block that was fetched or decoded.
   *
   * <p>Adds the payload to the segment if it maps to an unfetched position, updates metadata, and
   * may notify a waiting cross-segment. The method can iterate to process a further block that maps
   * to the same key while the state is hot, improving locality.
   *
   * @param key the node-level key associated with the provided data; used to resolve the
   *     segment-local index. Must not be {@code null}.
   * @param block the decoded block wrapper used for verification; its payload is provided
   *     separately via {@code decodedData}.
   * @param blockNumber preferred segment-local block index for {@code decodedData}; may be
   *     superseded if verification maps the data to a different slot.
   * @param decodedData exactly {@link CHKBlock#DATA_LENGTH} bytes of decoded block payload.
   * @return {@code true} if at least one block was saved to disk during this call; {@code false} if
   *     no data was persisted (e.g., duplicate, invalid, or write failure).
   * @throws IOException if persisting, the decoded payload to the segment's storage fails.
   */
  boolean innerOnGotKey(
      NodeCHK key,
      ClientCHKBlock block,
      SplitFileSegmentKeys keys,
      int blockNumber,
      byte[] decodedData)
      throws IOException {
    if (decodedData.length != CHKBlock.DATA_LENGTH) {
      handleTooShortBlock(blockNumber);
      return false;
    }
    boolean saved = false;
    do {
      SaveResult res = saveBlockIfEligibleAndGetNext(key, keys, blockNumber, decodedData);
      if (res.earlyReturn()) return saved;
      invokeCallbackIfPresent(res, blockNumber);
      if (res.saved()) handlePostSaveEffects(block, key, res, blockNumber);
      saved = saved || res.saved();
      blockNumber = res.nextBlockNumber();
    } while (blockNumber != -1);
    return saved;
  }

  private void handleTooShortBlock(int blockNumber) {
    if (isIgnorableLastBlock(blockNumber)) {
      LOG.warn("Ignoring last block");
    } else {
      parent.fail(
          new FetchException(FetchExceptionMode.SPLITFILE_ERROR, "Splitfile block is too short"));
    }
  }

  private boolean isIgnorableLastBlock(int blockNumber) {
    return blockNumber == dataBlocks - 1
        && this.segNo == parent.segments.length - 1
        && parent.lastBlockMightNotBePadded();
  }

  private void invokeCallbackIfPresent(SaveResult res, int blockNumber) {
    if (res.callback() != null) res.callback().onFetchedRelevantBlock(this, blockNumber);
  }

  private void handlePostSaveEffects(
      ClientCHKBlock block, NodeCHK key, SaveResult res, int blockNumber) {
    lazyWriteMetadata();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Got block {} ({}) for {} for {} written to {}",
          blockNumber,
          key,
          this,
          parent,
          res.slotNumber());
    parent.jobRunner.queueNormalOrDrop(
        _ -> {
          parent.fetcher.onFetchedBlock();
          return false;
        });
    tryStartDecode();
    parent.fetcher.maybeAddToBinaryBlob(block);
  }

  private record SaveResult(
      boolean earlyReturn,
      boolean saved,
      int nextBlockNumber,
      int slotNumber,
      SplitFileFetcherCrossSegmentStorage callback) {}

  private SaveResult saveBlockIfEligibleAndGetNext(
      NodeCHK key, SplitFileSegmentKeys keys, int blockNumber, byte[] decodedData)
      throws IOException {
    SplitFileFetcherCrossSegmentStorage callback = null;
    short nextBlockNumber;
    int slotNumber;
    synchronized (this) {
      if (succeeded || failed || finished) {
        if (LOG.isDebugEnabled()) LOG.debug("Already succeeded/finished/failed");
        return new SaveResult(true, false, -1, -1, null);
      }
      if (blockChooser.hasSucceeded(blockNumber)) {
        if (LOG.isDebugEnabled()) LOG.debug("Already have block {}", blockNumber);
        blockNumber = blockChooser.getBlockNumber(keys, key);
        if (LOG.isDebugEnabled()) LOG.debug("Trying block {}", blockNumber);
        return new SaveResult(false, false, blockNumber, -1, null);
      }
      if (blockChooser.successCount() >= blocksForDecode()) {
        if (LOG.isDebugEnabled()) LOG.debug("Already decoding");
        return new SaveResult(true, false, -1, -1, null);
      }
      slotNumber = findFreeSlot();
      assert (slotNumber != -1);
      blocksFetched[slotNumber] = blockNumber;
      blockChooser.onSuccess(blockNumber);
      RAFLock lock = parent.lockRAFOpen();
      try {
        writeDownloadedBlock(slotNumber, decodedData);
      } catch (IOException e) {
        blocksFetched[slotNumber] = -1;
        blockChooser.onUnSuccess(blockNumber);
        throw new IOException(
            "Unable to write downloaded block to disk for segment " + this + ", slot " + slotNumber,
            e);
      } finally {
        lock.unlock();
      }
      if (crossSegmentsByBlock != null && blockNumber < crossSegmentsByBlock.length) {
        callback = crossSegmentsByBlock[blockNumber];
      }
      nextBlockNumber = (short) blockChooser.getBlockNumber(keys, key);
      metadataDirty = true;
    }
    return new SaveResult(false, true, nextBlockNumber, slotNumber, callback);
  }

  private synchronized int findFreeSlot() {
    for (int i = 0; i < blocksFetched.length; i++) {
      if (blocksFetched[i] == -1) return i;
    }
    return -1;
  }

  /**
   * Caller must have already lock()'ed {@code parent.raf} and synchronized {@code this}.
   *
   * @param slotNumber destination slot within the segment (0-based), as chosen by the segment.
   * @param data exactly {@link CHKBlock#DATA_LENGTH} bytes of decoded block payload.
   * @throws IOException if writing the block to its on-disk location fails for any reason.
   */
  private synchronized void writeDownloadedBlock(int slotNumber, byte[] data) throws IOException {
    // Padding is not applied here; FEC maintains a fixed block size.
    if (data.length != CHKBlock.DATA_LENGTH) throw new IllegalArgumentException();
    if (slotNumber >= blocksForDecode()) throw new IllegalArgumentException();
    parent.writeBlock(this, slotNumber, data);
  }

  long blockOffset(int slotNumber) {
    if (slotNumber < dataBlocks) {
      return segmentBlockDataOffset + (long) slotNumber * CHKBlock.DATA_LENGTH;
    } else if (slotNumber >= (dataBlocks + crossSegmentCheckBlocks)) {
      slotNumber -= crossSegmentCheckBlocks;
      return segmentBlockDataOffset + (long) slotNumber * CHKBlock.DATA_LENGTH;
    } else {
      slotNumber -= dataBlocks;
      return segmentCrossCheckBlockDataOffset + (long) slotNumber * CHKBlock.DATA_LENGTH;
    }
  }

  /**
   * Write the metadata (status). Caller should already have taken {@code parent.raf.lock()} and
   * synchronized {@code this}. Metadata on disk is compact; when reconstructing from disk, we
   * validate and, where possible, correct inconsistencies.
   */
  private void innerWriteMetadata(boolean force) {
    if (!parent.persistent) return;
    synchronized (this) {
      if (!(force || metadataDirty)) return;
      if (LOG.isDebugEnabled()) LOG.debug("Writing metadata for {} for {}", segNo, parent);
      OutputStream cos = parent.writeChecksummedTo(segmentStatusOffset, segmentStatusPaddedLength);
      try {
        DataOutputStream dos = new DataOutputStream(cos);
        for (int s : blocksFetched) dos.writeInt(s);
        blockChooser.writeRetries(dos);
        dos.close();
      } catch (IOException e) {
        throw new java.io.UncheckedIOException("Failed writing segment metadata", e);
      }
      metadataDirty = false;
    }
  }

  /**
   * Reads the variable metadata (e.g., fetched order and retry counters) from the parent storage
   * and validates its checksum and bounds.
   *
   * @throws IOException if the backing storage cannot be read completely.
   * @throws StorageFormatException if values are out of range or duplicated in ways that violate
   *     invariants.
   * @throws ChecksumFailedException if the persisted checksum does not match the payload.
   */
  void readMetadata() throws IOException, StorageFormatException, ChecksumFailedException {
    byte[] buf = new byte[segmentStatusPaddedLength];
    try {
      parent.preadChecksummed(
          segmentStatusOffset, buf, 0, segmentStatusPaddedLength - parent.checksumLength);
    } catch (ChecksumFailedException e) {
      corruptMetadata = true;
      throw e;
    }
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(buf));
    for (int i = 0; i < blocksFetched.length; i++) {
      int s = dis.readInt();
      if (s < -1 || s >= totalBlocks())
        throw new StorageFormatException("Bogus block number in blocksFetched[" + i + "]: " + s);
      blocksFetched[i] = s;
      if (s >= 0) {
        if (!blockChooser.hasSucceeded(s)) {
          blockChooser.onSuccess(s);
        } else {
          throw new StorageFormatException("Duplicated block number in blocksFetched in " + this);
        }
      }
    }
    blockChooser.readRetries(dis);
    failedBlocks = blockChooser.countFailedBlocks();
    if (failedBlocks >= checkBlocks) {
      failedRetries = true;
    }
    dis.close();
  }

  /**
   * Computes the logical size, in bytes, of a segment's status record without checksum padding. The
   * status includes the fetched-block map and, when enabled, per-block retry counters.
   *
   * @param dataBlocks number of data blocks; must be non-negative.
   * @param checkBlocks number of FEC check blocks; must be non-negative.
   * @param crossCheckBlocks number of cross-segment check blocks; must be non-negative.
   * @param trackRetries whether retry counters are included in the status record.
   * @return the size in bytes of the status record prior to appending the checksum.
   */
  public static int storedSegmentStatusLength(
      int dataBlocks, int checkBlocks, int crossCheckBlocks, boolean trackRetries) {
    int fetchedBlocks = dataBlocks + crossCheckBlocks;
    int totalBlocks = dataBlocks + checkBlocks + crossCheckBlocks;
    return fetchedBlocks * 4 + (trackRetries ? (totalBlocks * 4) : 0);
  }

  /**
   * Computes the on-disk size of the status record, including its checksum trailer. Returns {@code
   * 0} when the segment is non-persistent.
   *
   * @param dataBlocks number of data blocks; must be non-negative.
   * @param checkBlocks number of check blocks; must be non-negative.
   * @param crossCheckBlocks number of cross-segment check blocks; must be non-negative.
   * @param trackRetries whether retry counters are included.
   * @param checksumLength length, in bytes, of the checksum trailer.
   * @param persistent whether metadata is written to disk.
   * @return total size in bytes of the stored status record, or {@code 0} for in-memory use only.
   */
  public static int paddedStoredSegmentStatusLength(
      int dataBlocks,
      int checkBlocks,
      int crossCheckBlocks,
      boolean trackRetries,
      int checksumLength,
      boolean persistent) {
    if (!persistent) return 0;
    return storedSegmentStatusLength(dataBlocks, checkBlocks, crossCheckBlocks, trackRetries)
        + checksumLength;
  }

  private int blocksForDecode() {
    return dataBlocks + crossSegmentCheckBlocks;
  }

  /**
   * Returns whether the segment has reached a terminal state: succeeded, canceled, or given up
   * after exhausting retries.
   *
   * @return {@code true} when no further work will be performed.
   */
  public synchronized boolean isFinished() {
    return finished || failed || failedRetries;
  }

  /**
   * Indicates whether a decoding is currently in progress or the segment is already finished.
   *
   * @return {@code true} if decoding is active or the segment has finished.
   */
  @SuppressWarnings("unused")
  public synchronized boolean isDecodingOrFinished() {
    return finished || failed || succeeded || tryDecode;
  }

  /**
   * Returns whether all required data blocks (and cross-segment check blocks, if any) were written
   * to their final location in the parent storage.
   *
   * @return {@code true} after successful decode and writeback.
   */
  public synchronized boolean hasSucceeded() {
    return succeeded;
  }

  /**
   * Writes the decoded data portion of this segment to the supplied stream in block order. The
   * final block may be truncated if the overall file length is not a multiple of {@link
   * CHKBlock#DATA_LENGTH}.
   *
   * @param os destination stream; the caller manages buffering and closing.
   * @throws IOException if an I/O error occurs while reading blocks or writing to {@code os}.
   */
  void writeToInner(OutputStream os) throws IOException {
    // If switching to readAllBlocks(), ensure to consider memory limits.
    for (int i = 0; i < dataBlocks; i++) { // Don't include cross-check blocks.
      byte[] buf = readBlock(i);
      if (i == dataBlocks - 1 && this.segNo == parent.segments.length - 1) {
        int length = (int) (parent.finalLength % CHKBlock.DATA_LENGTH);
        if (length == 0) length = CHKBlock.DATA_LENGTH;
        os.write(buf, 0, length);
      } else {
        os.write(buf);
      }
    }
  }

  /**
   * Read a single block from a specific slot, which could be any block number.
   *
   * @throws IOException If an error occurred reading the data from the disk.
   */
  private synchronized byte[] readBlock(int slotNumber) throws IOException {
    if (slotNumber >= blocksForDecode()) throw new IllegalArgumentException();
    return parent.readBlock(this, slotNumber);
  }

  /**
   * Records a non-fatal fetch failure for the given block number and updates retry/cooldown state.
   * The parent may be notified to adjust scheduling, and metadata may be lazily persisted.
   *
   * @param blockNumber the segment-local block number whose last attempt failed.
   */
  public void onNonFatalFailure(int blockNumber) {
    if (LOG.isDebugEnabled())
      LOG.debug("Non-fatal failure on block {} for {} for {}", blockNumber, this, parent);
    FailureOutcome outcome = handleNonFatalFailureState(blockNumber);
    if (outcome.write()) lazyWriteMetadata();
    if (outcome.givenUp()) parent.failedBlock();
    if (outcome.kill()) {
      if (crossSegmentsByBlock == null) {
        parent.failOnSegment(this);
      } else {
        parent.finishedEncoding(this);
      }
    }
    if (outcome.wake()) parent.maybeClearCooldown();
  }

  private record FailureOutcome(boolean givenUp, boolean kill, boolean wake, boolean write) {}

  private FailureOutcome handleNonFatalFailureState(int blockNumber) {
    synchronized (this) {
      long cooldown = blockChooser.overallCooldownTime();
      if (blockChooser.onNonFatalFailure(blockNumber)) {
        return outcomeOnGiveUp();
      } else {
        return outcomeOnRetry(blockNumber, cooldown);
      }
    }
  }

  private FailureOutcome outcomeOnGiveUp() {
    boolean givenUp = true;
    boolean kill = false;
    boolean write = false;
    failedBlocks++;
    int target = checkBlocks;
    if (!parent.lastBlockMightNotBePadded()) target++;
    if (failedBlocks >= target) {
      kill = true;
      failedRetries = true;
      if (crossSegmentsByBlock == null) {
        finished = true;
        failed = true;
      }
    } else {
      write = true;
    }
    if (write) metadataDirty = true;
    return new FailureOutcome(givenUp, kill, false, write);
  }

  private FailureOutcome outcomeOnRetry(int blockNumber, long cooldown) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Block {} on {} : {}/{}",
          blockNumber,
          this,
          blockChooser.getRetries(blockNumber),
          blockChooser.maxRetries);
    boolean wake = blockChooser.overallCooldownTime() < cooldown;
    metadataDirty = true;
    return new FailureOutcome(false, false, wake, true);
  }

  /**
   * The metadata has been updated. We should write it ... at some point. CALLER MUST SET
   * metadataDirty!
   */
  private void lazyWriteMetadata() {
    parent.lazyWriteMetadata();
  }

  /**
   * Allocate a cross-segment data block. Note that this algorithm must be reproduced exactly for
   * splitfile compatibility; the Random seed is actually determined by the splitfile metadata.
   *
   * @param seg The cross-segment to allocate a block for.
   * @param random PRNG seeded from the splitfile metadata, which determines which blocks to
   *     allocate deterministically.
   * @return The data block number allocated.
   */
  public int allocateCrossDataBlock(SplitFileFetcherCrossSegmentStorage seg, Random random) {
    int size = dataBlocks;
    if (crossDataBlocksAllocated == size) return -1;
    int x = 0;
    for (int i = 0; i < 10; i++) {
      x = random.nextInt(size);
      if (crossSegmentsByBlock[x] == null) {
        crossSegmentsByBlock[x] = seg;
        crossDataBlocksAllocated++;
        return x;
      }
    }
    for (int i = 0; i < size; i++) {
      x++;
      if (x == size) x = 0;
      if (crossSegmentsByBlock[x] == null) {
        crossSegmentsByBlock[x] = seg;
        crossDataBlocksAllocated++;
        return x;
      }
    }
    throw new IllegalStateException(
        "Unable to allocate cross data block even though have not used all slots up???");
  }

  /**
   * Allocate a cross-segment check block. Note that this algorithm must be reproduced exactly for
   * splitfile compatibility; the Random seed is actually determined by the splitfile metadata.
   *
   * @param seg The cross-segment to allocate a block for.
   * @param random PRNG seeded from the splitfile metadata, which determines which blocks to
   *     allocate deterministically.
   * @return The block number allocated (between dataBlocks and dataBlocks+crossSegmentCheckBlocks).
   */
  public int allocateCrossCheckBlock(SplitFileFetcherCrossSegmentStorage seg, Random random) {
    if (crossCheckBlocksAllocated == crossSegmentCheckBlocks) return -1;
    int x = dataBlocks + crossSegmentCheckBlocks - (1 + random.nextInt(crossSegmentCheckBlocks));
    for (int i = 0; i < crossSegmentCheckBlocks; i++) {
      x++;
      if (x == dataBlocks + crossSegmentCheckBlocks) x = dataBlocks;
      if (crossSegmentsByBlock[x] == null) {
        crossSegmentsByBlock[x] = seg;
        crossCheckBlocksAllocated++;
        return x;
      }
    }
    throw new IllegalStateException(
        "Unable to allocate cross check block even though have not used all slots up???");
  }

  static int storedKeysLength(
      int dataBlocks, int checkBlocks, boolean commonDecryptKey, int checksumLength) {
    return SplitFileSegmentKeys.storedKeysLength(dataBlocks, checkBlocks, commonDecryptKey)
        + checksumLength;
  }

  /**
   * Only called during creation. Writes the segment key list and its checksum; callers must not
   * trigger a read of the keys before they have been persisted.
   */
  void writeKeysWithChecksum(SplitFileSegmentKeys keys) throws IOException {
    assert Objects.equals(keysCache.get(), keys);
    assert (this.dataBlocks + this.crossSegmentCheckBlocks == keys.dataBlocks);
    assert (this.checkBlocks == keys.checkBlocks);
    OutputStream cos = parent.writeChecksummedTo(segmentKeyListOffset, segmentKeyListLength);
    DataOutputStream dos = new DataOutputStream(cos);
    try {
      keys.writeKeys(dos, false);
      keys.writeKeys(dos, true);
    } catch (IOException e) {
      // Impossible!
      throw new java.io.UncheckedIOException("Failed writing segment keys", e);
    }
    dos.close();
  }

  /**
   * Returns {@code true} if this segment currently wants the provided node-level key, based on its
   * internal chooser and completion state.
   *
   * @param key a node-level CHK identifying a candidate block.
   * @return {@code true} if the key maps to an unfetched block for this segment at this time.
   */
  public boolean definitelyWantKey(NodeCHK key) {
    synchronized (this) {
      if (succeeded || failed || finished) return false;
    }
    SplitFileSegmentKeys keys;
    try {
      keys = getSegmentKeys();
    } catch (IOException e) {
      parent.failOnDiskError(e);
      return false;
    }
    synchronized (this) { // Synced because of blocksFound
      return blockChooser.getBlockNumber(keys, key) >= 0;
    }
  }

  /**
   * Writes minimal, fixed metadata for the segment. This records sizes (not offsets). Cross-segment
   * assignments are written by the cross-segment structure.
   *
   * @param dos the destination stream that receives the fixed metadata; not closed by this method.
   * @throws IOException if the stream fails while writing the metadata fields.
   */
  public void writeFixedMetadata(DataOutputStream dos) throws IOException {
    dos.writeInt(this.dataBlocks);
    dos.writeInt(this.crossSegmentCheckBlocks);
    dos.writeInt(this.checkBlocks);
  }

  // For unit testing.

  synchronized boolean hasStartedDecode() {
    return succeeded || failed || finished || tryDecode;
  }

  synchronized boolean hasFailed() {
    return failed || failedRetries;
  }

  // Removed unused method: copyDownloadedBlocks()

  /**
   * Counts how many keys remain to be fetched for this segment at the time of the call. When the
   * segment is finished or decoding, the count is zero.
   *
   * @return a number of unfetched keys (data + check + cross-segment check) remaining.
   */
  public synchronized long countUnfetchedKeys() {
    if (finished || tryDecode) return 0;
    return (long) totalBlocks() - blockChooser.successCount();
  }

  /**
   * Counts the number of keys that are currently eligible to be sent to the fetcher, taking into
   * account cooldowns and retry limits.
   *
   * @return number of fetchable keys as of the call.
   */
  public synchronized long countSendableKeys() {
    if (finished || tryDecode) return 0;
    return blockChooser.countFetchable();
  }

  /**
   * Adds all currently unfetched node-level keys for this segment to the provided list. Keys are
   * read from the persisted key list and filtered by the current success state.
   *
   * @param keys the output list that is appended with missing keys; never cleared by this method.
   * @throws IOException if the key list cannot be read due to I/O or checksum failures.
   */
  public synchronized void getUnfetchedKeys(List<Key> keys) throws IOException {
    if (finished || tryDecode) return;
    SplitFileSegmentKeys keyList = getSegmentKeys();
    for (int i = 0; i < totalBlocks(); i++) {
      if (!blockChooser.hasSucceeded(i)) keys.add(keyList.getNodeKey(i, null, false));
    }
  }

  /**
   * Picks a segment-local block number to fetch next according to the internal chooser, without
   * mutating the persistent state. Cooldowns and in-memory retry bookkeeping may still be updated.
   *
   * @return a 0-based block number to fetch, or {@code -1} if no key is currently eligible.
   */
  public int chooseRandomKey() {
    int chosen = chooseKeyInternal();
    if (chosen == -1) {
      long cooldownTime = blockChooser.overallCooldownTime();
      if (cooldownTime > System.currentTimeMillis()) parent.increaseCooldown(cooldownTime);
      return -1;
    } else {
      return chosen;
    }
  }

  private int chooseKeyInternal() {
    synchronized (this) {
      if (finished) return -1;
      if (failedRetries) return -1;
      if (tryDecode) {
        if (LOG.isDebugEnabled()) LOG.debug("Segment decoding so not choosing a key on {}", this);
        return -1;
      }
      if (corruptMetadata)
        return -1; // Will be fetchable after we've found out what blocks we actually have.
      int chosen = blockChooser.chooseKey();
      if (chosen != -1) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Chosen key {}/{} for {} (retries {}/{})",
              chosen,
              totalBlocks(),
              this,
              blockChooser.getRetries(chosen),
              blockChooser.maxRetries);
      } else {
        if (LOG.isDebugEnabled()) LOG.debug("No keys chosen for {}", this);
      }
      return chosen;
    }
  }

  /**
   * Marks this segment as finished without completing decoding, typically because the higher-level
   * operation was canceled. If decode is in progress, the final callback is deferred until the
   * decoder reports back; otherwise the parent is notified immediately.
   */
  public void cancel() {
    boolean decoding;
    synchronized (this) {
      if (finished) return;
      finished = true;
      decoding = tryDecode;
      // If already decoding, must wait for the decoder to check in before completing shutdown.
    }
    if (!decoding) parent.finishedEncoding(this);
    // Else must wait.
  }

  /**
   * Returns the next absolute time (milliseconds from the epoch) before which this segment should
   * avoid scheduling new fetches due to cooldowns, or {@code 0} if no cooldown is in effect.
   *
   * @return epoch-millis timestamp until the next retry window, or {@code 0} when ready now.
   */
  public synchronized long getOverallCooldownTime() {
    if (finished || succeeded || failed || failedRetries) return 0;
    return blockChooser.overallCooldownTime();
  }

  synchronized long getCooldownTime(int blockNumber) {
    if (finished || succeeded || failed || failedRetries) return 0;
    return blockChooser.getCooldownTime(blockNumber);
  }

  synchronized boolean corruptMetadata() {
    return corruptMetadata;
  }

  /**
   * Reports whether the segment has collected enough distinct inputs to attempt FEC decode and is
   * not yet decoding.
   *
   * @return {@code true} when a decoding should be scheduled; otherwise {@code false}.
   */
  public synchronized boolean needsDecode() {
    if (finished || succeeded || failed) return false;
    if (tryDecode) return false;
    return blockChooser.successCount() == blocksForDecode();
  }

  /**
   * Returns the number of unique blocks successfully stored so far for this segment (data +
   * cross-segment check blocks).
   *
   * @return count of successfully stored unique blocks.
   */
  public synchronized int foundBlocks() {
    return blockChooser.successCount();
  }

  /**
   * Returns the number of blocks that have permanently failed after exhausting retries.
   *
   * @return count of permanently failed blocks contributing toward the failure threshold.
   */
  public synchronized int failedBlocks() {
    return failedBlocks;
  }

  /**
   * Returns the client-level key for the given segment-local block number, or {@code null} if keys
   * are unavailable or cannot be loaded at this time.
   *
   * @param blockNum 0-based segment-local block index.
   * @return the {@link ClientCHK} for {@code blockNum}, or {@code null} if the key list is missing
   *     or unreadable.
   */
  public synchronized ClientCHK getKey(int blockNum) {
    SplitFileSegmentKeys keys;
    try {
      keys = getSegmentKeys();
    } catch (IOException _) {
      return null;
    }
    if (keys == null) return null;
    return keys.getKey(blockNum, null, false);
  }

  /**
   * Verifies the stored payload for {@code blockNum} against its expected key and returns the
   * payload when valid. If verification fails, the block is marked unsucceeded and the segment is
   * reopened for completion.
   *
   * @param blockNum 0-based block number to validate and read.
   * @return a byte array of length {@link CHKBlock#DATA_LENGTH} with the block payload, or {@code
   *     null} if the block is not present or verification fails.
   * @throws IOException if the payload cannot be read from disk.
   */
  @SuppressWarnings("java:S1168")
  public synchronized byte[] checkAndGetBlockData(int blockNum) throws IOException {
    if (!blockChooser.hasSucceeded(blockNum)) return null;
    ClientCHK key = getKey(blockNum);
    if (key == null) return null;
    for (int i = 0; i < blocksFetched.length; i++) {
      if (blocksFetched[i] == blockNum) {
        byte[] buf = readBlock(i);
        try {
          ClientCHKBlock block =
              ClientCHKBlock.encodeSplitfileBlock(
                  buf, key.getCryptoKey(), key.getCryptoAlgorithm());
          if (!block.getClientKey().equals(key)) {
            LOG.error("Block {} in blocksFound[{}] is not valid!", blockNum, i);
            blockChooser.onUnSuccess(blockNum);
            succeeded = false;
            finished = false;
          } else {
            return buf;
          }
        } catch (CHKEncodeException e) {
          // Should not be possible.
          LOG.error("Impossible: {}", String.valueOf(e));
          return null;
        }
      }
    }
    LOG.error("Block {} in blocksFound but not in blocksFetched on {}", blockNum, this);
    return null;
  }

  synchronized void resumeCallback(int blockNo, SplitFileFetcherCrossSegmentStorage crossSegment) {
    this.crossSegmentsByBlock[blockNo] = crossSegment;
  }

  /**
   * Returns whether the given segment-local block number has been successfully fetched and stored.
   *
   * @param blockNo 0-based segment-local block index.
   * @return {@code true} if the block is currently recorded as present.
   */
  public synchronized boolean hasBlock(int blockNo) {
    return blockChooser.hasSucceeded(blockNo);
  }

  /**
   * Returns whether a decoding job has been scheduled and not yet completed for this segment.
   *
   * @return {@code true} while a decoding job is in progress.
   */
  public synchronized boolean isDecoding() {
    return tryDecode;
  }

  /** Called after checking datastore for a datastore-only request. */
  public void onFinishedCheckingDatastoreNoFetch() {
    synchronized (this) {
      if (tryDecode) return;
      if (succeeded) return;
      if (finished) return;
      if (failed) return;
      failed = true;
      finished = true;
    }
    parent.finishedEncoding(this);
  }
}

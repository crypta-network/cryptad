package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import network.crypta.client.FECCodec;
import network.crypta.client.async.PersistentJobRunner.CheckpointLock;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.ClientCHK;
import network.crypta.support.MemoryLimitedChunk;
import network.crypta.support.MemoryLimitedJob;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.api.LockableRandomAccessBuffer.RAFLock;
import network.crypta.support.io.CountedOutputStream;
import network.crypta.support.io.NullOutputStream;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates cross-segment parity generation for a single split-file segment.
 *
 * <p>This type owns the mapping of data and cross-check (parity) blocks that belong to one logical
 * segment but are physically distributed across multiple {@link SplitFileInserterSegmentStorage}
 * instances. It reads data blocks from their home segments, uses the {@link
 * network.crypta.client.FECCodec FECCodec} to compute cross-check blocks, and writes the resulting
 * parity back to the segment that hosts each cross-check slot. Operations are scheduled via a
 * {@link network.crypta.support.MemoryLimitedJobRunner MemoryLimitedJobRunner} so encoding can be
 * performed asynchronously under a memory budget.
 *
 * <p>Typical usage is:
 *
 * <ol>
 *   <li>Construct the instance and incrementally {@code addDataBlock(...)} / {@code
 *       addCheckBlock(...)} during layout.
 *   <li>Call {@link #startEncode(short)} once when all slots are assigned.
 *   <li>Observe progress via {@link #isFinishedEncoding()} or {@link #hasCompletedOrFailed()}; on
 *       persistence-enabled builds, {@link #storeStatus()} is called internally when encoding
 *       completes.
 * </ol>
 *
 * <p>Thread-safety: methods that mutate or read lifecycle state ({@code encoding}, {@code encoded},
 * {@code cancelled}) are synchronized. Encoding work itself executes on background threads provided
 * by the job runner. Instances are mutable and not intended for reuse across independent segments.
 *
 * @see SplitFileInserterStorage
 * @see SplitFileInserterSegmentStorage
 * @see network.crypta.client.FECCodec
 */
public final class SplitFileInserterCrossSegmentStorage {
  private static final Logger LOG =
      LoggerFactory.getLogger(SplitFileInserterCrossSegmentStorage.class);

  final SplitFileInserterStorage parent;
  final int segNo;
  final int dataBlockCount;
  final int crossCheckBlockCount;
  final int totalBlocks;

  private volatile boolean encoded;
  private boolean encoding;
  private boolean cancelled;

  /** Segment for each block */
  private final SplitFileInserterSegmentStorage[] segments;

  /** Block number within the segment for each block */
  private final int[] blockNumbers;

  // Only used in construction.
  private int counter;

  private final int statusLength;

  // Set to true to encode block keys during *cross-segment* encoding, and thus detect e.g., storage
  // bugs.
  // This will cause more disk I/O as we have to write the keys (more or less randomly).
  // Intended for additional verification during cross-segment encoding.
  static final boolean DEBUG_ENCODE = true;

  /**
   * Creates a cross-segment encoder for the specified segment.
   *
   * <p>The instance records the cross-segment placement of both data and cross-check blocks. The
   * {@code persistent} flag is passed for logging and status sizing; the parent storage determines
   * whether status is actually persisted. Call {@link #startEncode(short)} after all blocks for the
   * segment have been registered.
   *
   * @param parent the owning {@link SplitFileInserterStorage}; provides I/O, codec, and persistence
   *     services. Must be non-null and remain alive for the lifetime of this encoder.
   * @param segNo the zero-based segment number within the split file; used for addressing status
   *     and cross-check blocks.
   * @param persistent whether the overall insertion flow is configured for persistence; affects
   *     whether status lengths include a checksum footer and whether writes are attempted.
   * @param segLen number of data blocks in this segment. Must be positive and consistent with the
   *     parent/codec configuration.
   * @param crossCheckBlocks number of cross-check (parity) blocks for this segment. Must be
   *     positive and not exceed codec limits.
   */
  public SplitFileInserterCrossSegmentStorage(
      SplitFileInserterStorage parent,
      int segNo,
      boolean persistent,
      int segLen,
      int crossCheckBlocks) {
    this.parent = parent;
    this.segNo = segNo;
    this.dataBlockCount = segLen;
    this.crossCheckBlockCount = crossCheckBlocks;
    this.totalBlocks = dataBlockCount + crossCheckBlocks;
    segments = new SplitFileInserterSegmentStorage[totalBlocks];
    blockNumbers = new int[totalBlocks];
    try {
      CountedOutputStream cos = new CountedOutputStream(new NullOutputStream());
      DataOutputStream dos = new DataOutputStream(cos);
      innerStoreStatus(dos);
      dos.close();
      statusLength = (int) cos.written() + parent.checker.checksumLength();
    } catch (IOException e) {
      throw new IllegalStateException(e); // Impossible
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Constructed cross-segment; persistent={}, segLen={}, crossCheckBlocks={}",
          persistent,
          segLen,
          crossCheckBlocks);
    }
  }

  /** Only used during construction */
  private synchronized void addBlock(SplitFileInserterSegmentStorage seg, int blockNum) {
    segments[counter] = seg;
    blockNumbers[counter] = blockNum;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Allocated cross-segment block {} to block {} on {} for {}",
          counter,
          blockNum,
          seg,
          this);
    counter++;
  }

  synchronized void addDataBlock(SplitFileInserterSegmentStorage seg, int blockNum) {
    assert (counter < dataBlockCount);
    assert (blockNum < seg.dataBlockCount);
    addBlock(seg, blockNum);
  }

  /** Only used during construction */
  synchronized void addCheckBlock(SplitFileInserterSegmentStorage seg, int blockNum) {
    assert (counter >= dataBlockCount);
    assert (blockNum >= seg.dataBlockCount
        && blockNum < seg.dataBlockCount + seg.crossCheckBlockCount);
    addBlock(seg, blockNum);
  }

  /**
   * Writes the immutable placement settings of this cross-segment mapping.
   *
   * <p>The method serializes the data block count, cross-check block count, and for each logical
   * block the owning segment number and the block index within that segment, followed by the
   * computed per-segment status length. The stream is not closed by this method.
   *
   * @param dos destination stream to receive the fixed settings; must be open and writable. The
   *     caller retains ownership and is responsible for closing the stream.
   * @throws IOException if the underlying stream rejects writes or encounters an I/O error while
   *     writing settings.
   */
  public void writeFixedSettings(DataOutputStream dos) throws IOException {
    dos.writeInt(dataBlockCount);
    dos.writeInt(crossCheckBlockCount);
    for (int i = 0; i < totalBlocks; i++) {
      dos.writeInt(segments[i].segNo);
      dos.writeInt(blockNumbers[i]);
    }
    dos.writeInt(statusLength);
  }

  SplitFileInserterCrossSegmentStorage(
      SplitFileInserterStorage parent, DataInputStream dis, int segNo)
      throws StorageFormatException, IOException {
    this.segNo = segNo;
    this.parent = parent;
    this.dataBlockCount = dis.readInt();
    validatePositive(dataBlockCount, "Negative cross-segment data block count");
    this.crossCheckBlockCount = dis.readInt();
    validatePositive(crossCheckBlockCount, "Negative cross-check block count");
    this.totalBlocks = dataBlockCount + crossCheckBlockCount;
    validateTotalBlocks(totalBlocks);
    segments = new SplitFileInserterSegmentStorage[totalBlocks];
    blockNumbers = new int[totalBlocks];
    for (int i = 0; i < totalBlocks; i++) {
      int readSegmentNumber = dis.readInt();
      validateSegmentIndex(parent, readSegmentNumber);
      int readBlockNumber = dis.readInt();
      SplitFileInserterSegmentStorage segment = parent.segments[readSegmentNumber];
      validateBlockNumber(i, readBlockNumber, segment);
      segments[i] = segment;
      blockNumbers[i] = readBlockNumber;
    }
    for (int i = 0; i < crossCheckBlockCount; i++) {
      segments[i + dataBlockCount].setCrossCheckBlock(
          this, blockNumbers[i + dataBlockCount], i + dataBlockCount);
    }
    statusLength = dis.readInt();
    validateStatusLength(statusLength);
    verifyStoredStatusCapacity(parent, statusLength);
  }

  private static void validatePositive(int value, String message) throws StorageFormatException {
    if (value <= 0) throw new StorageFormatException(message);
  }

  private static void validateTotalBlocks(int total) throws StorageFormatException {
    if (total > FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT)
      throw new StorageFormatException("Bogus total block count");
  }

  private static void validateSegmentIndex(SplitFileInserterStorage parent, int segIdx)
      throws StorageFormatException {
    if (segIdx < 0 || segIdx >= parent.segments.length)
      throw new StorageFormatException("Bogus segment number " + segIdx);
  }

  private void validateBlockNumber(
      int slotIndex, int blockNumber, SplitFileInserterSegmentStorage segment)
      throws StorageFormatException {
    boolean outOfRange =
        blockNumber < 0 || blockNumber >= segment.dataBlockCount + segment.crossCheckBlockCount;
    boolean wrongTypeForSlot =
        (slotIndex < dataBlockCount && blockNumber >= segment.dataBlockCount)
            || (slotIndex >= dataBlockCount && blockNumber < segment.dataBlockCount);
    if (outOfRange || wrongTypeForSlot)
      throw new StorageFormatException(
          "Bogus block number " + blockNumber + " for slot " + slotIndex);
  }

  private static void validateStatusLength(int statusLength) throws StorageFormatException {
    if (statusLength < 0) throw new StorageFormatException("Bogus status length");
  }

  private void verifyStoredStatusCapacity(SplitFileInserterStorage parent, int storedLength)
      throws StorageFormatException {
    try {
      CountedOutputStream cos = new CountedOutputStream(new NullOutputStream());
      DataOutputStream dos = new DataOutputStream(cos);
      innerStoreStatus(dos);
      dos.close();
      int computedStatusLength = (int) cos.written() + parent.checker.checksumLength();
      if (computedStatusLength > storedLength)
        throw new StorageFormatException("Stored status length smaller than required");
    } catch (IOException e) {
      throw new IllegalStateException(e); // Impossible
    }
  }

  /**
   * Schedules asynchronous encoding of cross-check (parity) blocks for this segment.
   *
   * <p>The call is idempotent and returns immediately: when first invoked, it enqueues a
   * memory-bounded job that reads all data blocks, computes parity via the configured codec, writes
   * each cross-check block to its owning segment, and persists status where enabled. Subsequent
   * calls while encoding is in progress are ignored.
   *
   * @param prio relative scheduling priority forwarded to the job runner. The exact ordering
   *     semantics are defined by {@link network.crypta.support.MemoryLimitedJobRunner}.
   */
  public synchronized void startEncode(final short prio) {
    if (encoded) return;
    if (cancelled) return;
    if (encoding) return;
    encoding = true;
    long limit =
        (long) totalBlocks * CHKBlock.DATA_LENGTH
            + Math.max(
                parent.codec.maxMemoryOverheadDecode(dataBlockCount, crossCheckBlockCount),
                parent.codec.maxMemoryOverheadEncode(dataBlockCount, crossCheckBlockCount));
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
              innerEncode();
            } catch (PersistenceDisabledException _) {
              // Will be retried on restarting.
              shutdown = true;
            } finally {
              chunk.release();
              try {
                if (!shutdown) {
                  // We do want to call the callback even if we threw something, because we
                  // may be waiting to cancel. However, we DON'T call it if we are shutting down.
                  synchronized (SplitFileInserterCrossSegmentStorage.this) {
                    encoding = false;
                  }
                  parent.onFinishedEncoding(SplitFileInserterCrossSegmentStorage.this);
                }
              } finally {
                // Callback is part of the persistent job, unlock *after* calling it.
                if (lock != null) lock.unlock(false, MemoryLimitedJobRunner.THREAD_PRIORITY);
              }
            }
            return true;
          }
        });
  }

  /** Encode a segment. Much simpler than fetcher! */
  private void innerEncode() {
    try {
      synchronized (this) {
        if (cancelled) return;
      }
      if (LOG.isDebugEnabled()) LOG.debug("Encoding {}", this);
      byte[][] dataBlocks = readDataBlocks();
      byte[][] checkBlocks = new byte[crossCheckBlockCount][];
      for (int i = 0; i < checkBlocks.length; i++) checkBlocks[i] = new byte[CHKBlock.DATA_LENGTH];
      parent.codec.encode(
          dataBlocks, checkBlocks, new boolean[checkBlocks.length], CHKBlock.DATA_LENGTH);
      writeCheckBlocks(checkBlocks);
      synchronized (this) {
        encoded = true;
      }
      if (LOG.isDebugEnabled()) LOG.debug("Finished encoding {}", this);
      storeStatus();
    } catch (IOException e) {
      parent.failOnDiskError(e);
    }
  }

  private void writeCheckBlocks(byte[][] checkBlocks) throws IOException {
    RAFLock lock = parent.lockRAF();
    try {
      for (int i = 0; i < checkBlocks.length; i++) writeCheckBlock(i, checkBlocks[i]);
    } finally {
      lock.unlock();
    }
  }

  private void writeCheckBlock(int checkBlockNo, byte[] buf) throws IOException {
    parent.writeCheckBlock(segNo, checkBlockNo, buf);
    if (DEBUG_ENCODE) {
      SplitFileInserterSegmentStorage segment = segments[checkBlockNo + dataBlockCount];
      ClientCHK key = segment.encodeBlock(buf).getClientKey();
      segment.setKey(blockNumbers[checkBlockNo + dataBlockCount], key);
    }
  }

  /**
   * Reads a cross-check block for this cross-segment mapping and validates addressing.
   *
   * <p>The method asserts that the requested {@code segmentNumber} and {@code blockNoWithinSegment}
   * match the layout recorded during construction for the given {@code
   * slotNumberWithinCrossSegment}. On success, it returns the raw bytes of the cross-check block as
   * stored by the parent.
   *
   * @param slotNumberWithinCrossSegment zero-based slot index within this cross-segment (data
   *     blocks first, then cross-check blocks). Must reference a cross-check slot.
   * @param segmentNumber segment identifier that is expected to own the requested block; used for
   *     consistency assertions against the recorded mapping.
   * @param blockNoWithinSegment block index inside {@code segmentNumber} that is expected to match
   *     the recorded block number for the provided slot.
   * @return a newly allocated byte array containing the cross-check block data as stored on disk.
   * @throws IOException if the underlying storage cannot read the requested block, or an I/O error
   *     occurs during the read operation.
   */
  byte[] readCheckBlock(
      int slotNumberWithinCrossSegment, int segmentNumber, int blockNoWithinSegment)
      throws IOException {
    assert (blockNumbers[slotNumberWithinCrossSegment] == blockNoWithinSegment);
    assert (segments[slotNumberWithinCrossSegment].segNo == segmentNumber);
    return parent.readCheckBlock(segNo, slotNumberWithinCrossSegment - dataBlockCount);
  }

  private byte[][] readDataBlocks() throws IOException {
    RAFLock lock = parent.lockUnderlying();
    try {
      byte[][] data = new byte[dataBlockCount][];
      for (int i = 0; i < dataBlockCount; i++) {
        data[i] = segments[i].readDataBlock(blockNumbers[i]);
        if (DEBUG_ENCODE) {
          ClientCHK key = segments[i].encodeBlock(data[i]).getClientKey();
          segments[i].setKey(blockNumbers[i], key);
        }
      }
      return data;
    } finally {
      lock.unlock();
    }
  }

  /**
   * Returns whether parity generation finished successfully.
   *
   * <p>The flag flips to {@code true} after all cross-check blocks are written and the in-memory
   * status is updated. When persistence is enabled, status is also stored durably. While encoding
   * is still running, this method returns {@code false}.
   *
   * @return {@code true} when encoding completed without cancellation; {@code false} otherwise,
   *     including during in-flight encoding.
   */
  public synchronized boolean isFinishedEncoding() {
    return encoded;
  }

  /**
   * Reports how many block slots have been assigned to this cross-segment mapping so far.
   *
   * <p>The count reflects constructor-time allocation and includes both data and cross-check slots
   * that were registered via {@code addBlock(...)} variants during layout.
   *
   * @return the number of allocated block slots recorded at construction time.
   */
  public synchronized int getAllocatedCrossCheckBlocks() {
    return counter;
  }

  /**
   * Returns the number of bytes reserved for persisted status of this segment.
   *
   * <p>The value includes any checksum footer required by the parent storage. It can be used by
   * callers to size buffers when saving or restoring segment status.
   *
   * @return total bytes required to store the status record for this cross-segment encoder.
   */
  public long storedStatusLength() {
    return statusLength;
  }

  /**
   * Persists the current in-memory status for this segment when persistence is enabled.
   *
   * <p>The operation is a no-op if the parent storage is non-persistent. The method writes a small
   * record containing the segment number and the {@code encoded} flag using the parent’s
   * checksummed writer. Errors are logged and forwarded to the parent’s disk-error handler.
   */
  public void storeStatus() {
    if (!parent.persistent) return;
    DataOutputStream dos;
    try {
      dos =
          new DataOutputStream(
              parent.writeChecksummedTo(parent.crossSegmentStatusOffset(segNo), statusLength));
      innerStoreStatus(dos);
    } catch (IOException e) {
      LOG.error("Impossible: {}", e, e);
      return;
    }
    try {
      dos.close();
    } catch (IOException e) {
      LOG.error("I/O error writing segment status?: {}", e, e);
      parent.failOnDiskError(e);
    }
  }

  private void innerStoreStatus(DataOutputStream dos) throws IOException {
    dos.writeInt(segNo); // To make checksum different.
    dos.writeBoolean(encoded);
  }

  void readStatus() throws IOException, ChecksumFailedException, StorageFormatException {
    byte[] data = new byte[statusLength - parent.checker.checksumLength()];
    parent.preadChecksummed(parent.crossSegmentStatusOffset(segNo), data, 0, data.length);
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
    if (dis.readInt() != segNo) throw new StorageFormatException("Bad segment number");
    encoded = dis.readBoolean();
  }

  @SuppressWarnings("unused")
  int[] getSegmentNumbers() {
    int[] ret = new int[totalBlocks];
    for (int i = 0; i < totalBlocks; i++) ret[i] = segments[i].segNo;
    return ret;
  }

  @SuppressWarnings("unused")
  int[] getBlockNumbers() {
    return blockNumbers.clone();
  }

  /**
   * Cancel the encode.
   *
   * @return True if we can complete cancelling now, false if we are encoding, in which case the
   *     parent will get the usual callback when it is done.
   */
  public synchronized boolean cancel() {
    cancelled = true;
    return !encoding;
  }

  /**
   * Indicates whether the encoding job has either completed or been canceled.
   *
   * <p>The method returns {@code false} while the job is running. Once the job finishes it returns
   * {@code true} for both success and cancellation. Call {@link #isFinishedEncoding()} to
   * distinguish a successful completion from cancellation.
   *
   * @return {@code true} if the job is not running, and the segment is either encoded or was
   *     canceled; {@code false} while encoding is in progress.
   */
  public synchronized boolean hasCompletedOrFailed() {
    if (encoding) return false;
    return encoded || cancelled;
  }

  /** For tests only */
  synchronized boolean isEncoding() {
    return encoding;
  }

  /** For tests only */
  synchronized boolean hasEncodedSuccessfully() {
    return encoded;
  }
}

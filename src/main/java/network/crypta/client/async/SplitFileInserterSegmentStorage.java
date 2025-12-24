package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.util.Arrays;
import java.util.Random;
import network.crypta.client.FECCodec;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.async.PersistentJobRunner.CheckpointLock;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.node.SendableRequestItem;
import network.crypta.node.SendableRequestItemKey;
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
 * A single segment within a splitfile that is prepared and inserted into the network.
 *
 * <p>Each splitfile is divided into multiple segments; a segment, in turn, consists of data blocks
 * and two kinds of redundancy blocks: per-segment check blocks and cross-segment check blocks. This
 * class owns the per-segment state for one segment during an insert: tracking which blocks exist on
 * disk, generating and persisting keys, running FEC encoding, and coordinating block transmission.
 * It is instantiated either from fixed settings (for new inserts), or from persisted metadata (for
 * restarts).
 *
 * <p>Typical flow: the caller constructs the instance, optionally restores persisted status via
 * {@link #readStatus()}, and starts encoding using {@link #startEncode(short)}. As individual block
 * inserts succeed or fail, the owner forwards callbacks to {@link #onInsertedBlock(int, ClientCHK)}
 * and {@link #onFailure(int, InsertException)}. When all required blocks have been inserted, the
 * parent is notified and the segment is considered complete.
 *
 * <p>Thread-safety: methods that mutate or query completion state synchronize on {@code this}.
 * Encoding work is scheduled on a background runner and may call back into this instance. Callers
 * should not hold external locks when invoking methods that may perform I/O or schedule work.
 * Instances are mutable while an insert is in progress and become effectively read-only after
 * completion or cancellation.
 *
 * <ul>
 *   <li>Responsibilities: encode blocks, persist keys/status, choose next block
 *   <li>Notable behavior: lazy metadata writes; restart-friendly status format
 *   <li>Error handling: disk errors fail the parent; RNF may be treated as success under configured
 *       heuristics
 * </ul>
 *
 * @see SplitFileInserterStorage
 * @see SplitFileInserterSegmentBlockChooser
 */
public class SplitFileInserterSegmentStorage {
  private static final Logger LOG = LoggerFactory.getLogger(SplitFileInserterSegmentStorage.class);

  /**
   * Parameter object used to configure segment construction.
   *
   * <p>This simple builder groups the knobs required to create a segment: block counts,
   * cryptographic parameters, and block-choosing/codec related settings. Using an explicit
   * parameter object keeps the constructor readable and stable while allowing callers to assemble
   * values in a fluent style.
   *
   * <p>All fields are consumed as-is by the constructor; no validation is performed here.
   */
  public static final class Params {
    int dataBlocks;
    int checkBlocks;
    int crossCheckBlocks;
    int keyLength;
    byte splitfileCryptoAlgorithm;
    byte[] splitfileCryptoKey;
    Random random;
    int maxRetries;
    int consecutiveRNFsCountAsSuccess;
    KeysFetchingLocally keysFetching;

    Params() {}

    /**
     * Set the number of blocks used by this segment.
     *
     * @param data number of data blocks contributing raw payload bytes; must be non-negative and
     *     fit within codec limits.
     * @param check number of per-segment check blocks created by the encoder; non-negative value;
     *     combined with data size to form total.
     * @param cross number of cross-segment check blocks belonging to this segment; zero when
     *     cross-segment coding is disabled.
     * @return the same parameter object for fluent chaining; values are stored verbatim and
     *     validated by the constructor.
     */
    public Params blocks(int data, int check, int cross) {
      this.dataBlocks = data;
      this.checkBlocks = check;
      this.crossCheckBlocks = cross;
      return this;
    }

    /**
     * Set splitfile key properties used to derive {@link ClientCHK} values.
     *
     * @param keyLength on-disk key length in bytes, including any checksum; the constructor
     *     persists this for later reads.
     * @param cryptoAlgorithm algorithm identifier for splitfile crypto; values are
     *     implementation-defined and must match encoder/decoder.
     * @param cryptoKey raw splitfile crypto key; for modern splitfiles this is the same for every
     *     block and is not modified by this class.
     * @return the same parameter object for fluent chaining; fields are copied directly into the
     *     segment instance.
     */
    public Params keys(int keyLength, byte cryptoAlgorithm, byte[] cryptoKey) {
      this.keyLength = keyLength;
      this.splitfileCryptoAlgorithm = cryptoAlgorithm;
      this.splitfileCryptoKey = cryptoKey;
      return this;
    }

    /**
     * Set codec- and chooser-related options.
     *
     * @param random pseudo-random source used for deterministic selection of cross-segment blocks;
     *     seeded from splitfile metadata.
     * @param maxRetries maximum non-fatal retries per block before failing; a negative value
     *     typically disables retry limits.
     * @param consecutiveRNFsCountAsSuccess threshold for counting consecutive route-not-found
     *     events as success; zero disables this heuristic.
     * @param keysFetching strategy/provider used by the chooser to decide local fetching behavior
     *     while scheduling block inserts.
     * @return the same parameter object for fluent chaining; values are passed to the internal
     *     chooser unchanged.
     */
    public Params codec(
        Random random,
        int maxRetries,
        int consecutiveRNFsCountAsSuccess,
        KeysFetchingLocally keysFetching) {
      this.random = random;
      this.maxRetries = maxRetries;
      this.consecutiveRNFsCountAsSuccess = consecutiveRNFsCountAsSuccess;
      this.keysFetching = keysFetching;
      return this;
    }
  }

  final SplitFileInserterStorage parent;

  final int segNo;
  final int dataBlockCount;
  final int crossCheckBlockCount;
  final int checkBlockCount;
  final int totalBlockCount;

  /** Has the segment been encoded? If so, all the check blocks have been written. */
  private boolean encoded;

  private boolean encoding;

  private final int statusLength;

  /** Length of a single key stored on disk. Includes checksum. */
  private final int keyLength;

  // Populated by SplitFileInserterCrossSegmentStorage during construction.
  /** For each cross-segment block, the cross-segment responsible */
  private final SplitFileInserterCrossSegmentStorage[] crossSegmentBlockSegments;

  /** For each cross-segment block, the block number within that cross-segment */
  private final int[] crossSegmentBlockNumbers;

  private final boolean[] blocksHaveKeys;
  private int blocksWithKeysCounter;

  // These are only used in construction.
  private final boolean[] crossDataBlocksAllocated;
  private int crossDataBlocksAllocatedCount;
  private int crossCheckBlocksAllocatedCount;

  // These are also in parent, but we need them here for easy access, especially as we don't want to
  // make the byte[] visible.
  /** For modern splitfiles, the crypto key is the same for every block. */
  private final byte[] splitfileCryptoKey;

  /** Crypto algorithm is the same for every block. */
  private final byte splitfileCryptoAlgorithm;

  /** LOCKING: Locked with (this) as needs to access encoded in chooseBlock */
  private final SplitFileInserterSegmentBlockChooser blockChooser;

  private boolean metadataDirty;

  /** Set if the insert is cancelled. */
  private boolean cancelled;

  /**
   * Create a new segment using explicitly provided settings.
   *
   * <p>This constructor initializes counters, allocates in-memory structures, and computes the
   * fixed status record length that will be used for durable metadata. It does not perform any I/O
   * beyond sizing the status structure.
   *
   * @param parent owning storage that provides disk layout, codec, and callbacks; must outlive this
   *     segment and not be {@code null}.
   * @param segNo zero-based segment index within the splitfile; used in key and status encodings.
   * @param params grouped configuration containing block counts, crypto values, and chooser
   *     options; values are captured directly.
   */
  public SplitFileInserterSegmentStorage(
      SplitFileInserterStorage parent, int segNo, Params params) {
    this.parent = parent;
    this.segNo = segNo;
    this.dataBlockCount = params.dataBlocks;
    this.checkBlockCount = params.checkBlocks;
    this.crossCheckBlockCount = params.crossCheckBlocks;
    totalBlockCount = dataBlockCount + crossCheckBlockCount + checkBlockCount;
    this.keyLength = params.keyLength;
    crossSegmentBlockSegments = new SplitFileInserterCrossSegmentStorage[crossCheckBlockCount];
    crossSegmentBlockNumbers = new int[crossCheckBlockCount];
    blocksHaveKeys = new boolean[totalBlockCount];
    this.splitfileCryptoAlgorithm = params.splitfileCryptoAlgorithm;
    this.splitfileCryptoKey = params.splitfileCryptoKey;
    crossDataBlocksAllocated = new boolean[dataBlockCount + crossCheckBlockCount];
    blockChooser =
        new SplitFileInserterSegmentBlockChooser(
            this,
            totalBlockCount,
            params.random,
            params.maxRetries,
            params.keysFetching,
            params.consecutiveRNFsCountAsSuccess);
    try {
      CountedOutputStream cos = new CountedOutputStream(new NullOutputStream());
      DataOutputStream dos = new DataOutputStream(cos);
      innerStoreStatus(dos);
      dos.close();
      statusLength = (int) cos.written() + parent.checker.checksumLength();
    } catch (IOException e) {
      throw new IllegalStateException(e); // Impossible
    }
  }

  /**
   * Recreate a segment from on-disk fixed settings previously written by {@link
   * #writeFixedSettings(DataOutputStream)}.
   *
   * <p>The constructor reads basic block counts and status sizing, rebuilds chooser state, and
   * validates that values are within reasonable limits. It does not read per-block keys or variable
   * status; call {@link #readStatus()} for that after construction.
   *
   * @param parent owning storage context; provides codec, disk access, and checksum checker
   *     services required to restore this segment.
   * @param dis data stream positioned at the fixed-settings record for this segment; the stream is
   *     read but not closed by this constructor.
   * @param segNo zero-based segment index associated with this instance; used for basic validation
   *     and later offsets.
   * @param params grouped configuration carrying key length and crypto values; these are not read
   *     from the stream.
   * @throws IOException on I/O failures while reading from {@code dis}; the caller is responsible
   *     for stream lifetime and error handling.
   * @throws StorageFormatException if any count or size is inconsistent with expectations, codec
   *     limits, or the parent’s cross-segment configuration.
   */
  public SplitFileInserterSegmentStorage(
      SplitFileInserterStorage parent, DataInputStream dis, int segNo, Params params)
      throws IOException, StorageFormatException {
    this.parent = parent;
    this.segNo = segNo;
    this.keyLength = params.keyLength;
    dataBlockCount = dis.readInt();
    if (dataBlockCount < 0) throw new StorageFormatException("Bogus data block count");
    crossCheckBlockCount = dis.readInt();
    if (crossCheckBlockCount < 0) throw new StorageFormatException("Bogus cross-check block count");
    boolean parentHasNoCross = (parent.crossSegments == null || parent.crossSegments.length == 0);
    if ((crossCheckBlockCount == 0) != parentHasNoCross)
      throw new StorageFormatException("Cross-check block count inconsistent with parent");
    checkBlockCount = dis.readInt();
    if (checkBlockCount < 0) throw new StorageFormatException("Bogus check block count");
    totalBlockCount = dataBlockCount + crossCheckBlockCount + checkBlockCount;
    if (totalBlockCount > FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT)
      throw new StorageFormatException("Bogus total block count");
    this.statusLength = dis.readInt();
    if (statusLength < 0) throw new StorageFormatException("Bogus status length");
    crossSegmentBlockSegments = new SplitFileInserterCrossSegmentStorage[crossCheckBlockCount];
    crossSegmentBlockNumbers = new int[crossCheckBlockCount];
    blocksHaveKeys = new boolean[totalBlockCount];
    this.splitfileCryptoAlgorithm = params.splitfileCryptoAlgorithm;
    this.splitfileCryptoKey = params.splitfileCryptoKey;
    crossDataBlocksAllocated = new boolean[dataBlockCount + crossCheckBlockCount];
    blockChooser =
        new SplitFileInserterSegmentBlockChooser(
            this,
            totalBlockCount,
            params.random,
            params.maxRetries,
            params.keysFetching,
            params.consecutiveRNFsCountAsSuccess);
    try {
      CountedOutputStream cos = new CountedOutputStream(new NullOutputStream());
      DataOutputStream dos = new DataOutputStream(cos);
      innerStoreStatus(dos);
      dos.close();
      int minStatusLength = (int) cos.written() + parent.checker.checksumLength();
      if (minStatusLength > statusLength)
        throw new StorageFormatException("Bad status length (too short)");
    } catch (IOException e) {
      throw new IllegalStateException(e); // Impossible
    }
  }

  // These two are only used in construction...

  /**
   * Allocate a cross-segment data block. Note that this algorithm must be reproduced exactly for
   * splitfile compatibility; the Random seed is actually determined by the splitfile metadata.
   *
   * @param random PRNG seeded from the splitfile metadata, which determines which blocks to
   *     allocate in a deterministic manner.
   * @return The data block number allocated.
   */
  int allocateCrossDataBlock(Random random) {
    int size = dataBlockCount;
    if (crossDataBlocksAllocatedCount == size) return -1;
    int x = 0;
    for (int i = 0; i < 10; i++) {
      x = random.nextInt(size);
      if (!crossDataBlocksAllocated[x]) {
        crossDataBlocksAllocated[x] = true;
        crossDataBlocksAllocatedCount++;
        return x;
      }
    }
    for (int i = 0; i < size; i++) {
      x++;
      if (x == size) x = 0;
      if (!crossDataBlocksAllocated[x]) {
        crossDataBlocksAllocated[x] = true;
        crossDataBlocksAllocatedCount++;
        return x;
      }
    }
    throw new IllegalStateException(
        "Unable to allocate cross data block even though have not used all slots up???");
  }

  /**
   * Allocate a cross-segment check block. **Note that this algorithm must be reproduced exactly for
   * splitfile compatibility**; the Random seed is actually determined by the splitfile metadata.
   *
   * @param seg The cross-segment to allocate a block for.
   * @param random PRNG seeded from the splitfile metadata, which determines which blocks to
   *     allocate in a deterministic manner.
   * @param crossSegmentBlockNumber Block number within the cross-segment.
   * @return The block number allocated (between dataBlockCount and
   *     dataBlockCount+crossSegmentCheckBlocks).
   */
  int allocateCrossCheckBlock(
      SplitFileInserterCrossSegmentStorage seg, Random random, int crossSegmentBlockNumber) {
    if (crossCheckBlocksAllocatedCount == crossCheckBlockCount) return -1;
    int x = crossCheckBlockCount - (1 + random.nextInt(crossCheckBlockCount));
    for (int i = 0; i < crossCheckBlockCount; i++) {
      x++;
      if (x == crossCheckBlockCount) x = 0;
      if (crossSegmentBlockSegments[x] == null) {
        crossSegmentBlockSegments[x] = seg;
        crossSegmentBlockNumbers[x] = crossSegmentBlockNumber;
        crossCheckBlocksAllocatedCount++;
        return x + dataBlockCount;
      }
    }
    throw new IllegalStateException(
        "Unable to allocate cross check block even though have not used all slots up???");
  }

  /**
   * Persist the current status for this segment when appropriate.
   *
   * <p>When persistence is enabled and the overall insert is still active, this method writes the
   * status record unless metadata is already up-to-date. The write is skipped when the segment has
   * been cancelled, and failures are reported back to the parent as disk errors.
   *
   * @param force when {@code true}, write status regardless of the in-memory dirty flag; when
   *     {@code false}, write only if metadata changed.
   */
  public void storeStatus(boolean force) {
    if (!parent.persistent) return;
    if (parent.hasFinished()) return;
    try {
      DataOutputStream dos;
      synchronized (this) {
        if (!force && !metadataDirty) return;
        if (cancelled) return;
        dos = openAndWriteStatusLocked();
        if (dos == null) {
          // Keep metadataDirty set so we retry on the next opportunity.
          return;
        }
        metadataDirty = false;
      }
      // Outside the lock is safe since if we fail we will fail the whole splitfile.
      dos.close();
    } catch (IOException e) {
      LOG.error("I/O error writing segment status?: {}", e, e);
      parent.failOnDiskError(e);
    }
  }

  private DataOutputStream openAndWriteStatusLocked() {
    try {
      DataOutputStream dos =
          new DataOutputStream(
              parent.writeChecksummedTo(parent.segmentStatusOffset(segNo), statusLength));
      innerStoreStatus(dos);
      return dos;
    } catch (IOException e) {
      LOG.error("Impossible: {}", e, e);
      return null;
    }
  }

  private void innerStoreStatus(DataOutputStream dos) throws IOException {
    dos.writeInt(segNo); // To make checksum different.
    dos.writeBoolean(encoded);
    blockChooser.write(dos);
  }

  /**
   * Read and restore the variable status for this segment from disk.
   *
   * <p>Only the variable portion is read; fixed settings are consumed by the constructor. The
   * checksum is verified before decoding.
   *
   * @throws IOException on I/O failures while reading the status area.
   * @throws ChecksumFailedException if the stored checksum does not match the status payload,
   *     indicating corruption.
   * @throws StorageFormatException if the decoded data is structurally inconsistent (for example,
   *     wrong segment number).
   */
  public void readStatus() throws IOException, ChecksumFailedException, StorageFormatException {
    byte[] data = new byte[statusLength - parent.checker.checksumLength()];
    parent.preadChecksummed(parent.getOffsetSegmentStatus(segNo), data, 0, data.length);
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));
    if (dis.readInt() != segNo) throw new StorageFormatException("Bad segment number");
    encoded = dis.readBoolean();
    blockChooser.read(dis);
  }

  /**
   * Return the byte length reserved on disk for this segment’s status.
   *
   * @return the total status record length including checksum bytes as used by the {@link
   *     ChecksumChecker}.
   */
  public long storedStatusLength() {
    return statusLength;
  }

  /**
   * Write the fixed settings for this segment to the provided stream.
   *
   * <p>The encoded values include the data, cross-check, and check block counts and the precomputed
   * status length. Callers are responsible for the stream’s lifetime.
   *
   * @param dos destination stream positioned for writing; not closed by this method.
   * @throws IOException if writing to {@code dos} fails for any reason.
   */
  public void writeFixedSettings(DataOutputStream dos) throws IOException {
    dos.writeInt(dataBlockCount);
    dos.writeInt(crossCheckBlockCount);
    dos.writeInt(checkBlockCount);
    dos.writeInt(statusLength);
  }

  static int getKeyLength(SplitFileInserterStorage parent) {
    return encodeKey(1, 1, ClientCHK.TEST_KEY, parent.hasSplitfileKey(), parent.checker).length;
  }

  private static byte[] encodeKey(
      int segNo, int blockNumber, ClientCHK key, boolean hasSplitfileKey, ChecksumChecker checker) {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    try {
      dos.writeInt(segNo);
      dos.writeInt(blockNumber);
      dos.writeByte(1); // 1 = present, 0 = not present
      innerWriteKey(key, dos, hasSplitfileKey);
      dos.close();
    } catch (IOException e) {
      throw new IllegalStateException(e); // Impossible
    }
    byte[] fullBuf = baos.toByteArray();
    byte[] bufNoKeyNumber = Arrays.copyOfRange(fullBuf, 8, fullBuf.length);
    return checker.appendChecksum(bufNoKeyNumber);
  }

  static void innerWriteKey(ClientCHK key, DataOutputStream dos, boolean hasSplitfileKey)
      throws IOException {
    if (hasSplitfileKey) {
      dos.write(key.getRoutingKey());
    } else {
      key.writeRawBinaryKey(dos);
    }
  }

  void clearKeys() throws IOException {
    // Just write 0's. Not valid.
    // Could be optimized to write the lot at once if needed.
    byte[] buf = new byte[keyLength];
    for (int i = 0; i < totalBlockCount; i++) {
      parent.innerWriteSegmentKey(segNo, i, buf);
    }
  }

  void setKey(int blockNumber, ClientCHK key) throws IOException {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Setting key {} for block {} on {}", key, blockNumber, this, new Exception("debug"));
    try {
      ClientCHK oldKey = readKey(blockNumber);
      if (!oldKey.equals(key))
        throw new IOException(
            "Key for block has changed! Data corruption or bugs in SplitFileInserter code");
    } catch (MissingKeyException _) {
      // Ok.
      writeKey(blockNumber, key);
    }
    // Must be called either way as we don't regenerate blocksHaveKeys on startup.
    setHasKey(blockNumber);
  }

  /**
   * Write a key for a block.
   *
   * @param blockNumber the block number; can be a data block, a cross-segment check block, or a
   *     per-segment check block, in that numerical order.
   * @param key the key to write for the specified block; must match the deterministically generated
   *     value.
   * @throws IOException if the key cannot be written to the underlying storage.
   */
  void writeKey(int blockNumber, ClientCHK key) throws IOException {
    byte[] buf = encodeKey(segNo, blockNumber, key, parent.hasSplitfileKey(), parent.checker);
    parent.innerWriteSegmentKey(segNo, blockNumber, buf);
  }

  /**
   * Set a flag indicating that we have a key. Call parent.onHasKeys if we have all of them. Note
   * that this structure is not persisted!
   */
  private void setHasKey(int blockNumber) {
    synchronized (this) {
      if (blocksHaveKeys[blockNumber]) return;
      blocksHaveKeys[blockNumber] = true;
      blocksWithKeysCounter++;
      if (blocksWithKeysCounter != totalBlockCount) return;
    }
    parent.onHasKeys(this);
  }

  /**
   * Return whether keys for all blocks in this segment are available.
   *
   * <p>The result is computed from in-memory flags that are updated when keys are read or written;
   * it is not recalculated from disk on startup unless {@link #checkKeys()} is used.
   *
   * @return {@code true} when all data, cross-check, and check block keys are known for this
   *     segment; {@code false} otherwise.
   */
  public synchronized boolean hasKeys() {
    return blocksWithKeysCounter == totalBlockCount;
  }

  /**
   * Validate that keys exist for all blocks when the segment claims to be encoded.
   *
   * <p>On mismatch (e.g., due to disk loss), the segment is marked as not yet encoded so it can be
   * re-encoded. Disk I/O errors are forwarded to the parent and fail the whole insert.
   */
  public void checkKeys() {
    synchronized (this) {
      if (!encoded) return;
    }
    try {
      for (int i = 0; i < totalBlockCount; i++) {
        readKey(i);
      }
    } catch (IOException e) {
      parent.failOnDiskError(e);
    } catch (MissingKeyException _) {
      // Easy to recover so may as well...
      LOG.error("Missing key even though segment encoded. Recovering by re-encoding...");
      synchronized (this) {
        encoded = false;
      }
    }
  }

  /**
   * Return the total number of bytes reserved for keys of this segment.
   *
   * @return the product of {@code keyLength} and total block count, matching the on-disk layout
   *     used by the parent.
   */
  public int storedKeysLength() {
    return keyLength * totalBlockCount;
  }

  /**
   * Read the raw data block for the given index.
   *
   * @param blockNo zero-based data block index; must be within {@code [0, dataBlockCount)}.
   * @return a new byte array containing {@link CHKBlock#DATA_LENGTH} bytes of payload.
   * @throws IOException if reading from the underlying storage fails.
   * @throws IllegalArgumentException if the index is outside the data range.
   */
  public byte[] readDataBlock(int blockNo) throws IOException {
    if (blockNo < 0 || blockNo >= dataBlockCount)
      throw new IllegalArgumentException("Invalid data block index: " + blockNo);
    return parent.readSegmentDataBlock(segNo, blockNo);
  }

  private void writeCheckBlock(int checkBlockNo, byte[] buf) throws IOException {
    parent.writeSegmentCheckBlock(segNo, checkBlockNo, buf);
  }

  /**
   * Read a per-segment check block by index.
   *
   * @param checkBlockNo zero-based check block index; must be within {@code [0, checkBlockCount)}.
   * @return a new byte array containing {@link CHKBlock#DATA_LENGTH} bytes of encoded check data.
   * @throws IOException if reading from the underlying storage fails.
   * @throws IllegalArgumentException if the index is outside the check range.
   */
  public byte[] readCheckBlock(int checkBlockNo) throws IOException {
    if (checkBlockNo < 0 || checkBlockNo >= checkBlockCount)
      throw new IllegalArgumentException("Invalid check block index: " + checkBlockNo);
    return parent.readSegmentCheckBlock(segNo, checkBlockNo);
  }

  /**
   * Schedule encoding of this segment at the given priority.
   *
   * <p>Encoding computes check and cross-check blocks from the current data, persists generated
   * keys, and marks the segment as encoded on success. Work runs asynchronously under the
   * memory-limited job runner. Repeated calls are idempotent while encoding is in progress or after
   * completion.
   *
   * @param prio scheduling priority used by the memory-limited job runner; the exact scale is
   *     defined by the runner implementation.
   */
  public synchronized void startEncode(final short prio) {
    if (encoded) return;
    if (encoding) return;
    encoding = true;
    int blocksTotal = dataBlockCount + checkBlockCount + crossCheckBlockCount;
    long limit =
        (long) blocksTotal * CHKBlock.DATA_LENGTH
            + Math.max(
                parent.codec.maxMemoryOverheadDecode(dataBlockCount, crossCheckBlockCount),
                parent.codec.maxMemoryOverheadEncode(dataBlockCount, crossCheckBlockCount));
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Scheduling encode on {} at priority {} blocks {} memory limit {}",
          this,
          prio,
          blocksTotal,
          limit);
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
              afterEncode(shutdown, lock);
            }
            return true;
          }
        });
  }

  private void afterEncode(boolean shutdown, CheckpointLock lock) {
    try {
      if (!shutdown) {
        // We do want to call the callback even if we threw something, because we
        // may be waiting to cancel. However, we DON'T call it if we are shutting down.
        synchronized (SplitFileInserterSegmentStorage.this) {
          encoding = false;
        }
        parent.onFinishedEncoding(SplitFileInserterSegmentStorage.this);
      }
    } finally {
      // Callback is part of the persistent job, unlock *after* calling it.
      if (lock != null) lock.unlock(false, MemoryLimitedJobRunner.THREAD_PRIORITY);
    }
  }

  private void innerEncode() {
    RAFLock lock = null;
    try {
      synchronized (this) {
        if (cancelled) return;
      }
      lock = parent.lockRAF();
      if (LOG.isDebugEnabled()) LOG.debug("Encoding {} for {}", this, parent);
      byte[][] dataBlocks = readDataAndCrossCheckBlocks();
      generateKeys(dataBlocks, 0);
      byte[][] checkBlocks = new byte[checkBlockCount][];
      for (int i = 0; i < checkBlocks.length; i++) checkBlocks[i] = new byte[CHKBlock.DATA_LENGTH];
      parent.codec.encode(
          dataBlocks, checkBlocks, new boolean[checkBlocks.length], CHKBlock.DATA_LENGTH);
      for (int i = 0; i < checkBlocks.length; i++) writeCheckBlock(i, checkBlocks[i]);
      generateKeys(checkBlocks, dataBlockCount + crossCheckBlockCount);
      synchronized (this) {
        encoded = true;
      }
      if (LOG.isDebugEnabled()) LOG.debug("Encoded {} for {}", this, parent);
    } catch (IOException e) {
      parent.failOnDiskError(e);
    } catch (RuntimeException t) {
      LOG.error("Failed: {}", t, t);
      parent.fail(new InsertException(InsertExceptionMode.INTERNAL_ERROR, t, null));
    } finally {
      if (lock != null) lock.unlock();
    }
  }

  /**
   * Generate keys for each block and record them.
   *
   * @throws IOException if persisting a generated key for any block fails due to an I/O error in
   *     the underlying storage.
   */
  private void generateKeys(byte[][] dataBlocks, int offset) throws IOException {
    for (int i = 0; i < dataBlocks.length; i++) {
      setKey(i + offset, encodeBlock(dataBlocks[i]).getClientKey());
    }
  }

  private byte[][] readDataAndCrossCheckBlocks() throws IOException {
    byte[][] data = new byte[dataBlockCount + crossCheckBlockCount][];
    RAFLock lock = parent.lockUnderlying();
    try {
      for (int i = 0; i < dataBlockCount; i++) data[i] = readDataBlock(i);
    } finally {
      lock.unlock();
    }
    for (int i = 0; i < crossCheckBlockCount; i++)
      data[i + dataBlockCount] = readCrossCheckBlock(i);
    return data;
  }

  private byte[] readCrossCheckBlock(int blockNo) throws IOException {
    return crossSegmentBlockSegments[blockNo].readCheckBlock(
        crossSegmentBlockNumbers[blockNo], segNo, blockNo + dataBlockCount);
  }

  /**
   * Return whether encoding for this segment has completed.
   *
   * @return {@code true} when all per-segment and cross-segment check blocks have been generated
   *     and written; {@code false} otherwise.
   */
  public synchronized boolean isFinishedEncoding() {
    return encoded;
  }

  /**
   * For unit tests. Generally for concurrency purposes we want something that won't change back,
   * hence e.g. isFinishedEncoding().
   */
  synchronized boolean isEncoding() {
    return encoding;
  }

  /**
   * Encode the specified block into a {@link ClientCHKBlock} suitable for insertion.
   *
   * <p>This method reads the block content (data, cross-check, or check) based on the index,
   * validates preconditions (not already successfully inserted), and applies the splitfile crypto.
   * It does not modify persistent state.
   *
   * @param blockNo zero-based block index spanning data, cross-check, and check regions.
   * @return an immutable encoded block that exposes the derived {@linkplain ClientCHK client key}
   *     for uploads.
   * @throws IOException if the block cannot be read or if an already-inserted block is requested.
   */
  public ClientCHKBlock encodeBlock(int blockNo) throws IOException {
    if (parent.isFinishing()) {
      throw new IOException(
          "Already finishing reading block " + blockNo + " for " + this + " for " + parent);
    }
    synchronized (this) {
      if (this.blockChooser.hasSucceeded(blockNo)) {
        LOG.error("Already inserted block {} for {} for {}", blockNo, this, parent);
        throw new IOException(
            "Already inserted block " + blockNo + " for " + this + " for " + parent);
      }
    }
    byte[] buf = readBlock(blockNo);
    return encodeBlock(buf);
  }

  private byte[] readBlock(int blockNo) throws IOException {
    assert (blockNo >= 0 && blockNo < totalBlockCount);
    if (blockNo < dataBlockCount) return readDataBlock(blockNo);
    else if (blockNo < dataBlockCount + crossCheckBlockCount)
      return readCrossCheckBlock(blockNo - dataBlockCount);
    else return readCheckBlock(blockNo - (dataBlockCount + crossCheckBlockCount));
  }

  ClientCHKBlock encodeBlock(byte[] buf) {
    assert (buf.length == CHKBlock.DATA_LENGTH);
    ClientCHKBlock block;
    try {
      block =
          ClientCHKBlock.encodeSplitfileBlock(buf, splitfileCryptoKey, splitfileCryptoAlgorithm);
    } catch (CHKEncodeException e) {
      throw new IllegalStateException(e); // Impossible!
    }
    return block;
  }

  private ClientCHK innerReadKey(DataInputStream dis) throws IOException {
    if (splitfileCryptoKey != null) {
      byte[] routingKey = new byte[32];
      dis.readFully(routingKey);
      return new ClientCHK(
          routingKey, splitfileCryptoKey, false, splitfileCryptoAlgorithm, (short) -1);
    } else {
      return new ClientCHK(dis);
    }
  }

  ClientCHK readKey(int blockNumber) throws IOException, MissingKeyException {
    byte[] buf = parent.innerReadSegmentKey(segNo, blockNumber);
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(buf));
    byte b = dis.readByte();
    if (b != 1) throw new MissingKeyException();
    ClientCHK key = innerReadKey(dis);
    setHasKey(blockNumber);
    if (LOG.isTraceEnabled()) LOG.trace("Returning {}", key);
    return key;
  }

  /**
   * Signals that a requested per-block key is not present on disk.
   *
   * <p>Thrown by {@link #readKey(int)} when the on-disk marker indicates the key is missing.
   * Callers typically trigger re-encoding to regenerate keys in such cases.
   */
  public static class MissingKeyException extends Exception {
    @Serial private static final long serialVersionUID = -6695311996193392803L;

    /**
     * Construct a new exception indicating the requested key is missing.
     *
     * <p>No detail message or cause is set. This mirrors the previously implicit default
     * constructor to retain behavior and binary compatibility.
     */
    public MissingKeyException() {
      super();
    }
  }

  /**
   * Return whether all required blocks for this segment have been inserted.
   *
   * <p>The outcome is final under normal operation. In rare circumstances involving local data loss
   * (for example, keys removed from disk), the state may be reconsidered by higher layers.
   *
   * @return {@code true} if the chooser reports success for all required blocks; {@code false} if
   *     any block remains or the segment was cancelled.
   */
  public synchronized boolean hasSucceeded() {
    if (cancelled) return false;
    return blockChooser.hasSucceededAll();
  }

  /**
   * Return whether all check and cross-check blocks have been encoded.
   *
   * @return {@code true} when encoding finished and state was updated; {@code false} otherwise.
   */
  public synchronized boolean hasEncoded() {
    return encoded;
  }

  /**
   * Notify this segment that a block insert succeeded.
   *
   * <p>The method records the key when not already present, updates chooser state, and triggers a
   * lazy metadata write. The parent callback is invoked when success completes the segment.
   *
   * @param blockNo zero-based block index whose insert succeeded.
   * @param key the {@link ClientCHK} associated with the inserted block; must match the value
   *     previously recorded or be absent.
   */
  public void onInsertedBlock(int blockNo, ClientCHK key) {
    try {
      if (parent.hasFinished()) return;
      this.setKey(blockNo, key);
      if (blockChooser.onSuccess(blockNo)) parent.callback.onInsertedBlock();
      lazyWriteMetadata();
    } catch (IOException e) {
      if (parent.hasFinished()) return; // Race condition possible as this is a callback
      parent.failOnDiskError(e);
    }
  }

  /** Called by the chooser when all blocks in this segment have been inserted. */
  void onInsertedAllBlocks() {
    if (LOG.isDebugEnabled()) LOG.debug("Inserted all blocks in segment {}", this);
    synchronized (this) {
      if (!encoded) return;
    }
    parent.segmentSucceeded(this);
  }

  /**
   * Notify this segment that a block insert attempt failed.
   *
   * <p>Fatal failures immediately fail the parent. Route-not-found events may be treated as success
   * under configuration, provided the key exists. Non-fatal failures contribute to retry
   * accounting; exceeding the limit fails the parent.
   *
   * @param blockNo zero-based block index whose insert failed.
   * @param e the insert exception describing the failure mode; not {@code null}.
   */
  public void onFailure(int blockNo, InsertException e) {
    if (LOG.isDebugEnabled())
      LOG.debug("Failed block {} with {} for {} for {}", blockNo, e, this, parent);
    if (parent.hasFinished()) return; // Race condition possible as this is a callback
    parent.addFailure(e);
    if (e.isFatal()) {
      parent.failFatalErrorInBlock();
      return;
    }

    if (handleRNFIfApplicable(blockNo, e)) return;

    if (blockChooser.onNonFatalFailure(blockNo)) {
      parent.failTooManyRetriesInBlock();
    } else {
      if (blockChooser.maxRetries >= 0) lazyWriteMetadata();
      parent.clearCooldown();
    }
  }

  private boolean handleRNFIfApplicable(int blockNo, InsertException e) {
    if (e.mode == InsertExceptionMode.ROUTE_NOT_FOUND
        && blockChooser.consecutiveRNFsCountAsSuccess > 0) {
      try {
        readKey(blockNo);
        blockChooser.onRNF(blockNo);
        parent.clearCooldown();
        return true;
      } catch (MissingKeyException _) {
        LOG.error("RNF but no key on block {} on {}", blockNo, this);
        return false;
      } catch (IOException e1) {
        if (parent.hasFinished()) return true; // Race condition possible as this is a callback
        parent.failOnDiskError(e1);
        return true;
      }
    } else if (blockChooser.consecutiveRNFsCountAsSuccess > 0 && blockChooser.pushRNFs(blockNo)) {
      parent.failTooManyRetriesInBlock();
      return true;
    }
    return false;
  }

  private void lazyWriteMetadata() {
    synchronized (this) {
      metadataDirty = true;
    }
    parent.lazyWriteMetadata();
  }

  /**
   * Return whether the segment has reached a terminal state.
   *
   * @return {@code true} when encoding finished or cancellation has been processed; {@code false}
   *     while encoding is still running.
   */
  public synchronized boolean hasCompletedOrFailed() {
    if (encoded) return true; // No more encoding jobs will run.
    if (encoding) return false; // Waiting for job to finish.
    if (cancelled) return true;
    return blockChooser.hasSucceededAll();
  }

  /**
   * Request cancellation of this segment.
   *
   * <p>The caller must separately check {@link #hasCompletedOrFailed()} after all segments are
   * cancelled to observe completion of any in-flight encode work.
   *
   * @return {@code true} if the segment is now done (no work pending); {@code false} if an encode
   *     was already in progress and a callback will be issued to the parent when it finishes.
   */
  public synchronized boolean cancel() {
    if (cancelled) return false;
    cancelled = true;
    return hasCompletedOrFailed();
  }

  /**
   * Choose the next block to insert according to the internal policy.
   *
   * @return a {@link BlockInsert} handle representing the chosen block, or {@code null} if no
   *     further blocks should be sent at this time.
   */
  public synchronized BlockInsert chooseBlock() {
    int chosenBlock = innerChooseBlock();
    if (chosenBlock == -1) return null;
    return new BlockInsert(this, chosenBlock);
  }

  synchronized int innerChooseBlock() {
    if (cancelled) return -1;
    return blockChooser.chooseKey();
  }

  /**
   * Immutable handle representing a single pending block insert.
   *
   * <p>The object serves both as the request item and as its key; equality and hashing include the
   * owning segment and the block number only.
   */
  public static final class BlockInsert implements SendableRequestItemKey, SendableRequestItem {

    final SplitFileInserterSegmentStorage segment;
    final int blockNumber;
    final int hashCode;

    BlockInsert(SplitFileInserterSegmentStorage segment, int blockNumber) {
      this.segment = segment;
      this.blockNumber = blockNumber;
      hashCode = computeHashCode();
    }

    private int computeHashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + blockNumber;
      result = prime * result + ((segment == null) ? 0 : segment.hashCode());
      return result;
    }

    @Override
    public int hashCode() {
      return hashCode;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) return true;
      if (obj == null) return false;
      if (!(obj instanceof BlockInsert other)) return false;
      if (blockNumber != other.blockNumber) return false;
      return segment == other.segment;
    }

    @Override
    public void dump() {
      // Do nothing. We don't encode in advance.
    }

    @Override
    public SendableRequestItemKey getKey() {
      return this;
    }

    public String toString() {
      return "BlockInsert:" + segment + ":" + blockNumber + "@memory:" + super.hashCode();
    }
  }

  /**
   * Set the cross-segment associated with a cross-check block, which tells us how to read that
   * block from disk.
   *
   * @param crossSegment The cross-segment.
   * @param segmentBlockNumber The block number within this segment
   * @param crossSegmentBlockNumber The cross-check block number (usually between 0 and 2
   *     inclusive).
   */
  void setCrossCheckBlock(
      SplitFileInserterCrossSegmentStorage crossSegment,
      int segmentBlockNumber,
      int crossSegmentBlockNumber) {
    crossSegmentBlockSegments[segmentBlockNumber - dataBlockCount] = crossSegment;
    crossSegmentBlockNumbers[segmentBlockNumber - dataBlockCount] = crossSegmentBlockNumber;
  }

  /**
   * Return the number of keys currently eligible for sending.
   *
   * @return a non-negative count of keys the chooser deems fetchable at the moment; used for
   *     scheduling decisions by the parent.
   */
  public int countSendableKeys() {
    return blockChooser.countFetchable();
  }

  public String toString() {
    return super.toString() + ":" + parent;
  }
}

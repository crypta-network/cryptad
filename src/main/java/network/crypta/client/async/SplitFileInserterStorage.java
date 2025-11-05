package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FECCodec;
import network.crypta.client.FailureCodeTracker;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.Metadata;
import network.crypta.client.Metadata.SplitfileAlgorithm;
import network.crypta.client.MetadataParseException;
import network.crypta.client.async.SplitFileInserterSegmentStorage.BlockInsert;
import network.crypta.client.async.SplitFileInserterSegmentStorage.MissingKeyException;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.MasterSecret;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.ClientCHK;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.support.HexUtil;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.RandomArrayIterator;
import network.crypta.support.Ticker;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBuffer.RAFLock;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.NullBucket;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.RAFInputStream;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;
import network.crypta.support.math.MersenneTwister;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Persistent and transient storage for splitfile inserts.
 *
 * <p>This component encapsulates the on-disk (or in-memory) representation of an ongoing splitfile
 * insert. It maintains fixed settings, per-segment metadata, optional cross-segment redundancy
 * mappings, encoded check/cross-check blocks, per-segment status, and the list of generated keys.
 * The storage is separate from the original content and is designed to support resume, progress
 * reporting, and integrity verification without requiring the inserter runtime to be resident.
 *
 * <p>When used persistently, the file layout is checksummed in bounded sections and includes: (1)
 * magic/version and global settings; (2) per-segment fixed settings; (3) optional cross-segment
 * settings; (4) optional padded last data block; (5) overall status; (6) cross-check and check
 * blocks; (7) per-segment and per-cross-segment status; and (8) per-segment keys. The class focuses
 * on deterministic encoding and storage; the higher-level scheduling and network I/O are handled by
 * {@link SplitFileInserter} via callbacks.
 *
 * <p>Thread-safety: instances are used by worker threads under a simple state machine. Methods that
 * mutate shared state either synchronize internally or rely on the caller to serialize access via
 * the surrounding inserter. The original data buffer and RAF implementations are expected to be
 * safe for concurrent reads/writes according to their own contracts.
 *
 * <ul>
 *   <li>Responsibilities: encode per-segment/cross-segment settings; store and read checksummed
 *       sections; surface progress and failures to the callback; support resume and lazy metadata
 *       writing.
 *   <li>Notable behaviors: non-redundant mode omits check and cross-check data; offsets and lengths
 *       are validated when resuming; operations use a {@link ChecksumChecker} to protect section
 *       boundaries against corruption.
 * </ul>
 */
public class SplitFileInserterStorage {
  private static final Logger LOG = LoggerFactory.getLogger(SplitFileInserterStorage.class);

  /** The original file to upload */
  final LockableRandomAccessBuffer originalData;

  /** The RAF containing check blocks, status etc. */
  private final LockableRandomAccessBuffer raf;

  private final long rafLength;

  /** Is the request persistent? */
  final boolean persistent;

  final SplitFileInserterStorageCallback callback;

  final SplitFileInserterSegmentStorage[] segments;
  final SplitFileInserterCrossSegmentStorage[] crossSegments;

  /** Random iterator for segment selection. LOCKING: cooldownLock must be held. */
  private final RandomArrayIterator<SplitFileInserterSegmentStorage> randomSegmentIterator;

  final int totalDataBlocks;
  final int totalCheckBlocks;

  /** FEC codec used to encode check and cross-check blocks */
  final FECCodec codec;

  /**
   * Length in bytes of the data being uploaded, i.e. the original file, ignoring padding, check
   * blocks etc.
   */
  final long dataLength;

  // These are kept for creating Metadata etc.
  /** MIME type etc. */
  private final ClientMetadata clientMetadata;

  /** Is the splitfile metadata? */
  private final boolean isMetadata;

  /**
   * Compression codec that should be used to decompress the data. We do not do the compression
   * here, but we need it to generate the Metadata.
   */
  private final COMPRESSOR_TYPE compressionCodec;

  /** Length of the file after decompression. */
  private final long decompressedLength;

  /** For reinserting old splitfiles etc. */
  private final CompatibilityMode cmode;

  private final byte[] hashThisLayerOnly;
  private final ARCHIVE_TYPE archiveType;

  // Top level stuff
  private final HashResult[] hashes;
  private final boolean topDontCompress;
  final int topRequiredBlocks;
  final int topTotalBlocks;
  private final long origDataSize;
  private final long origCompressedDataSize;

  /** Type of splitfile */
  private final SplitfileAlgorithm splitfileType;

  /** Nominal number of data blocks per segment. */
  private final int segmentSize;

  /** Nominal number of check blocks per segment. */
  private final int checkSegmentSize;

  /**
   * Number of segments which have 1 fewer block than segmentSize. Not necessarily valid for very
   * old compatibility modes.
   */
  private final int deductBlocksFromSegments;

  /** Number of cross-check blocks per segment and therefore also per cross-segment. */
  private final int crossCheckBlocks;

  /** For modern splitfiles, the crypto key is the same for every block. */
  private final byte[] splitfileCryptoKey;

  /** Crypto algorithm is the same for every block. */
  private final byte splitfileCryptoAlgorithm;

  /**
   * If true, the splitfile crypto key must be included in the metadata. If false, it was
   * auto-generated so can be left implicit.
   */
  private final boolean specifySplitfileKeyInMetadata;

  // Misc settings
  final ChecksumChecker checker;

  /** Length of a key as stored on disk */
  private final int keyLength;

  private final int maxRetries;
  private final int consecutiveRNFsCountAsSuccess;

  // System utilities.
  final MemoryLimitedJobRunner memoryLimitedJobRunner;
  final PersistentJobRunner jobRunner;
  final Ticker ticker;
  final Random random;

  /**
   * True if the size of the file is not exactly divisible by one block. If so, we have the last
   * block, after padding, stored in raf. (This means we can change the padding algorithm slightly
   * more easily)
   */
  private final boolean hasPaddedLastBlock;

  /**
   * Status. Generally depends on the status of the individual segments... Not persisted: Can be
   * deduced from the state of the segments, except for the last 3 states, which are only used
   * during completion (we don't keep the storage around once we're finished).
   */
  enum Status {
    NOT_STARTED,
    STARTED,
    ENCODED_CROSS_SEGMENTS,
    ENCODED,
    GENERATING_METADATA,
    SUCCEEDED,
    FAILED
  }

  private Status status;
  private final FailureCodeTracker errors;
  private boolean overallStatusDirty;

  // Not persisted, only used briefly during completion
  private InsertException failing;

  // These are kept here so we can set them in the main constructor after
  // we've constructed the segments.

  /** Offset in originalData to the start of each data segment */
  private final long[] underlyingOffsetDataSegments;

  private final long offsetPaddedLastBlock;
  private final long offsetOverallStatus;
  private final long[] offsetCrossSegmentBlocks;
  private final long[] offsetSegmentCheckBlocks;
  private final long[] offsetSegmentStatus;
  private final long[] offsetCrossSegmentStatus;
  private final long[] offsetSegmentKeys;

  private final int overallStatusLength;

  private final Object cooldownLock = new Object();
  private boolean noBlocksToSend;

  /**
   * Constructs a new storage instance for a splitfile insert from live inputs.
   *
   * <p>This constructor computes the segment layout, initializes per-segment and optional
   * cross-segment structures, and, when {@code persistent} is true, materializes a checksummed RAF
   * that can be used to resume the insert after a process restart. No network activity occurs here;
   * the caller controls lifecycle and scheduling via the associated inserter callback.
   *
   * @param originalData buffer providing random access to the original content; must support block
   *     reads throughout the insert and remain valid until completion. Not closed by this method.
   * @param decompressedLength total length of the uncompressed data in bytes; used for metadata
   *     generation when compression is applied.
   * @param callback callback sink for progress and state changes; must remain valid during the
   *     insert; never {@code null}.
   * @param compressionCodec compression codec identifier for metadata; does not perform compression
   *     here; may be {@code null} for uncompressed.
   * @param meta client metadata to embed in the final descriptor; fields are copied as needed and
   *     may be minimal for non-metadata inserts.
   * @param isMetadata whether this splitfile represents metadata rather than user content; affects
   *     compatibility and key handling.
   * @param archiveType archive type for metadata generation; may be {@code null} if not applicable.
   * @param rafFactory factory used to create the RAF backing store for check blocks and status;
   *     persistent implementations must survive process restarts.
   * @param persistent true to create a resume-capable RAF on disk; false for transient in-memory
   *     operation with minimal bookkeeping.
   * @param ctx insert context providing limits, compatibility mode, and policy knobs; consulted to
   *     compute segment sizing and redundancy.
   * @param splitfileCryptoAlgorithm splitfile crypto algorithm code as defined by {@link
   *     Metadata#isValidSplitfileCryptoAlgorithm(byte)}.
   * @param splitfileCryptoKey explicit 32-byte key for splitfile encryption; when {@code null}, the
   *     key may be derived from {@code hashThisLayerOnly} or {@code hashes} depending on mode.
   * @param hashThisLayerOnly 32-byte content hash used to derive the implicit key for current
   *     layer; may be {@code null} when deriving from aggregate hashes.
   * @param hashes optional array of block or layer hashes available for key derivation and
   *     metadata; may be {@code null} in older compatibility modes.
   * @param bf bucket factory for temporary encoding of settings sections; implementations must
   *     allow small in-memory buckets.
   * @param checker checksum strategy used to wrap sections with a length and checksum; determines
   *     the checksum type persisted in the header.
   * @param random PRNG used for deterministic cross-segment allocation and retry strategy; seeded
   *     by the caller for reproducibility.
   * @param memoryLimitedJobRunner executor that enforces per-task memory accounting; used for
   *     encoding jobs across segments and cross-segments.
   * @param jobRunner persistent job runner used to queue metadata writing and other background
   *     work; must tolerate drops when resources are constrained.
   * @param ticker ticker used for timed callbacks and scheduling; supplies the executor used by
   *     this storage for asynchronous work.
   * @param keysFetching interface to query local key cache/state to bias encoding and retries; may
   *     be a no-op in tests.
   * @param topDontCompress whether to disable top-level compression in metadata; this influences
   *     the final descriptor only.
   * @param topRequiredBlocks count of data blocks that must succeed for decoding; storage will add
   *     its own accounting for check/cross-check overhead.
   * @param topTotalBlocks total data blocks present at the top level; storage augments this with
   *     check and cross-check counts.
   * @param origDataSize original byte length before any containerization; copied into metadata as a
   *     hint.
   * @param origCompressedDataSize original compressed length in bytes when available; used for
   *     metadata reporting.
   * @throws IOException if writing the initial persistent RAF fails due to I/O problems.
   * @throws InsertException if a temporary bucket fails, inputs are inconsistent, or limits are
   *     violated during initialization.
   */
  public SplitFileInserterStorage(
      LockableRandomAccessBuffer originalData,
      long decompressedLength,
      SplitFileInserterStorageCallback callback,
      COMPRESSOR_TYPE compressionCodec,
      ClientMetadata meta,
      boolean isMetadata,
      ARCHIVE_TYPE archiveType,
      LockableRandomAccessBufferFactory rafFactory,
      boolean persistent,
      InsertContext ctx,
      byte splitfileCryptoAlgorithm,
      byte[] splitfileCryptoKey,
      byte[] hashThisLayerOnly,
      HashResult[] hashes,
      BucketFactory bf,
      ChecksumChecker checker,
      Random random,
      MemoryLimitedJobRunner memoryLimitedJobRunner,
      PersistentJobRunner jobRunner,
      Ticker ticker,
      KeysFetchingLocally keysFetching,
      boolean topDontCompress,
      int topRequiredBlocks,
      int topTotalBlocks,
      long origDataSize,
      long origCompressedDataSize)
      throws IOException, InsertException {
    this.originalData = originalData;
    this.callback = callback;
    this.persistent = persistent;
    dataLength = originalData.size();
    if (dataLength > ((long) Integer.MAX_VALUE) * CHKBlock.DATA_LENGTH)
      throw new InsertException(InsertExceptionMode.TOO_BIG);
    totalDataBlocks = (int) ((dataLength + CHKBlock.DATA_LENGTH - 1) / CHKBlock.DATA_LENGTH);
    this.decompressedLength = decompressedLength;
    this.compressionCodec = compressionCodec;
    this.clientMetadata = meta;
    this.checker = checker;
    this.memoryLimitedJobRunner = memoryLimitedJobRunner;
    this.jobRunner = jobRunner;
    this.isMetadata = isMetadata;
    this.archiveType = archiveType;
    this.hashThisLayerOnly = hashThisLayerOnly;
    this.topDontCompress = topDontCompress;
    this.origDataSize = origDataSize;
    this.origCompressedDataSize = origCompressedDataSize;
    this.maxRetries = ctx.maxInsertRetries;
    this.errors = new FailureCodeTracker(true);
    this.ticker = ticker;
    this.random = random;

    // Work out how many blocks in each segment, crypto keys etc.
    // Complicated by back compatibility, i.e. the need to be able to
    // reinsert old splitfiles.
    // Consider getting rid of support for very old splitfiles.

    cmode = ctx.getCompatibilityMode();
    if (cmode.ordinal() < CompatibilityMode.COMPAT_1255.ordinal()) {
      this.hashes = null;
      splitfileCryptoKey = null;
    } else {
      this.hashes = hashes;
    }

    SegmentLayout layout = computeSegmentLayout(totalDataBlocks, ctx, cmode);
    int segs = layout.segs;
    this.segmentSize = layout.segmentSize;
    this.deductBlocksFromSegments = layout.deductBlocksFromSegments;

    int computedCrossCheckBlocks = computeCrossCheckBlocks(segs, cmode);

    this.splitfileType = ctx.getSplitfileAlgorithm();
    this.codec = FECCodec.getInstance(splitfileType);

    // When NONREDUNDANT, the codec is null and there are no check/cross-check blocks.
    if (this.codec == null) {
      this.crossCheckBlocks = 0;
      checkSegmentSize = 0;
    } else {
      this.crossCheckBlocks = computedCrossCheckBlocks;
      checkSegmentSize = codec.getCheckBlocks(segmentSize + computedCrossCheckBlocks, cmode);
    }

    this.splitfileCryptoAlgorithm = splitfileCryptoAlgorithm;
    CryptoInit crypto =
        chooseSplitfileKey(splitfileCryptoKey, cmode, hashThisLayerOnly, this.hashes);
    this.splitfileCryptoKey = crypto.key;
    specifySplitfileKeyInMetadata = crypto.specifyInMetadata;

    int totalCheckBlocksLocal = 0;
    int checkTotalDataBlocks = 0;
    underlyingOffsetDataSegments = new long[segs];
    keyLength = SplitFileInserterSegmentStorage.getKeyLength(this);
    this.consecutiveRNFsCountAsSuccess = ctx.consecutiveRNFsCountAsSuccess;
    segments =
        makeSegments(
            segmentSize,
            segs,
            totalDataBlocks,
            deductBlocksFromSegments,
            keysFetching,
            consecutiveRNFsCountAsSuccess);
    randomSegmentIterator = new RandomArrayIterator<>(segments);
    for (SplitFileInserterSegmentStorage segment : segments) {
      totalCheckBlocksLocal += segment.checkBlockCount;
      checkTotalDataBlocks += segment.dataBlockCount;
    }
    assert (checkTotalDataBlocks == totalDataBlocks);
    this.totalCheckBlocks = totalCheckBlocksLocal;

    // Allocate cross-segment structures only for the actual configured count.
    // In NON_REDUNDANT mode (codec == null), this.crossCheckBlocks is 0 even if
    // computedCrossCheckBlocks would suggest redundancy for large segment counts.
    crossSegments =
        initCrossSegmentsIfAny(segs, this.crossCheckBlocks, segmentSize, deductBlocksFromSegments);

    // Now set up the RAF.

    // Setup offset arrays early so we can compute the length of encodeOffsets().
    OffsetArrays oa = createOffsetArrays(persistent);
    offsetCrossSegmentBlocks = oa.offsetCrossSegmentBlocks;
    offsetCrossSegmentStatus = oa.offsetCrossSegmentStatus;
    offsetSegmentCheckBlocks = oa.offsetSegmentCheckBlocks;
    offsetSegmentStatus = oa.offsetSegmentStatus;
    offsetSegmentKeys = oa.offsetSegmentKeys;

    // First we have all the fixed stuff ...

    byte[] paddedLastBlock = null;
    if (dataLength % CHKBlock.DATA_LENGTH != 0) {
      this.hasPaddedLastBlock = true;
      long from = (dataLength / CHKBlock.DATA_LENGTH) * CHKBlock.DATA_LENGTH;
      byte[] buf = new byte[(int) (dataLength - from)];
      this.originalData.pread(from, buf, 0, buf.length);
      paddedLastBlock = BucketTools.pad(buf, CHKBlock.DATA_LENGTH, buf.length);
    } else {
      this.hasPaddedLastBlock = false;
    }

    byte[] header = null;
    Bucket segmentSettings = null;
    Bucket crossSegmentSettings = null;
    int offsetsLength = 0;
    if (persistent) {
      PersistenceInit p = preparePersistenceInit(bf);
      header = p.header;
      segmentSettings = p.segmentSettings;
      crossSegmentSettings = p.crossSegmentSettings;
      offsetsLength = p.offsetsLength;
    }

    long ptr = 0;
    if (persistent) {
      ptr = calculateInitialPtr(header, offsetsLength, segmentSettings, crossSegmentSettings);
      offsetOverallStatus = ptr;
      overallStatusLength = encodeOverallStatus().length;
      ptr = padTo4096(ptr + overallStatusLength);
    } else {
      overallStatusLength = 0;
      offsetOverallStatus = 0;
    }

    this.offsetPaddedLastBlock = ptr;

    if (hasPaddedLastBlock) ptr += CHKBlock.DATA_LENGTH;

    ptr = populateCrossSegmentOffsets(ptr);

    ptr = populateSegmentCheckOffsets(ptr);

    ptr = populateStatusOffsetsIfPersistent(ptr);

    ptr = populateSegmentKeyOffsets(ptr);

    rafLength = ptr;
    this.raf = rafFactory.makeRAF(ptr);
    writeInitialRafIfPersistent(header, offsetsLength, segmentSettings, crossSegmentSettings);
    writePaddedLastBlockIfAny(paddedLastBlock);
    clearInitialStatusesIfPersistent();
    // Encrypted RAFs are not initialised with 0's, so we need to clear explicitly (we do store keys
    // even for transient inserts).
    for (SplitFileInserterSegmentStorage segment : segments) {
      segment.clearKeys();
    }
    // Keys are empty, and invalid.
    status = Status.NOT_STARTED;

    // Include the cross-check blocks in the required blocks. The actual number needed may be
    // slightly less, but this is consistent with fetching, and also with pre-1468 metadata.
    int totalCrossCheckBlocks = crossCheckBlocks * segments.length;
    this.topRequiredBlocks = topRequiredBlocks + totalDataBlocks + totalCrossCheckBlocks;
    this.topTotalBlocks =
        topTotalBlocks + totalDataBlocks + totalCrossCheckBlocks + totalCheckBlocks;

    this.writeMetadataJob = createWriteMetadataJob();
    this.wrapLazyWriteMetadata = () -> jobRunner.queueNormalOrDrop(writeMetadataJob);
  }

  /**
   * Reconstructs storage state from a previously persisted RAF.
   *
   * <p>This constructor validates the file format, verifies each checksummed section, restores the
   * original data reference, and rebuilds per-segment and optional cross-segment state. It throws
   * descriptive exceptions when the header is invalid, checksums fail, offsets are out of range, or
   * the original data size does not match the stored header.
   *
   * @param raf random access buffer containing the persisted insert state; the caller must open and
   *     resume it prior to invocation and retain ownership for closing.
   * @param originalData random access buffer for the original content; must be resumed by the
   *     caller and match the size stored in the header exactly.
   * @param callback parent callback interface that receives progress notifications and final
   *     outcomes; typically provided by the surrounding inserter.
   * @param random PRNG used by the restored storage for allocation and retry decisions; should be
   *     non-deterministic in production and fixed in tests when reproducibility is required.
   * @param memoryLimitedJobRunner executor enforcing memory budgets across encoding tasks; used by
   *     segment and cross-segment encoders.
   * @param jobRunner runner for background persistence work such as deferred metadata writing.
   * @param ticker ticker providing the timed executor used by background jobs.
   * @param keysFetching interface to query whether keys are locally present or recently failed;
   *     influences scheduling and retry heuristics.
   * @param persistentFG filename generator used to restore temporary files referenced by the RAF.
   * @param persistentFileTracker tracker used by {@code BucketTools.restoreRAFFrom} to resolve file
   *     handles in a safe, verified manner.
   * @param masterKey master secret for decrypting encrypted RAF sections when applicable.
   * @throws IOException if reading the RAF fails due to I/O errors while restoring sections.
   * @throws StorageFormatException if the file format is invalid, contains out-of-range values, or
   *     violates invariants expected by this version.
   * @throws ChecksumFailedException if any checksummed section fails verification during restore.
   * @throws ResumeFailedException if the supplied {@code originalData} size differs from the stored
   *     value or is otherwise incompatible with the header.
   */
  public SplitFileInserterStorage(
      LockableRandomAccessBuffer raf,
      LockableRandomAccessBuffer originalData,
      SplitFileInserterStorageCallback callback,
      Random random,
      MemoryLimitedJobRunner memoryLimitedJobRunner,
      PersistentJobRunner jobRunner,
      Ticker ticker,
      KeysFetchingLocally keysFetching,
      FilenameGenerator persistentFG,
      PersistentFileTracker persistentFileTracker,
      MasterSecret masterKey)
      throws IOException, StorageFormatException, ChecksumFailedException, ResumeFailedException {
    this.persistent = true;
    this.callback = callback;
    this.ticker = ticker;
    this.memoryLimitedJobRunner = memoryLimitedJobRunner;
    this.jobRunner = jobRunner;
    this.random = random;
    this.raf = raf;
    rafLength = raf.size();
    InputStream ois = new RAFInputStream(raf, 0, rafLength);
    DataInputStream dis = new DataInputStream(ois);
    validateMagic(dis.readLong());
    int checksumType = dis.readInt();
    this.checker = createChecksumChecker(checksumType);

    long maxLength = Long.MAX_VALUE;

    InputStream is = checker.checksumReaderWithLength(ois, new ArrayBucketFactory(), maxLength);
    dis = new DataInputStream(is);
    validateVersion(dis.readInt());
    LockableRandomAccessBuffer rafOrig =
        BucketTools.restoreRAFFrom(dis, persistentFG, persistentFileTracker, masterKey);
    this.originalData = chooseOriginalData(originalData, rafOrig);
    this.totalDataBlocks = readPositiveInt(dis, "total data blocks");
    this.totalCheckBlocks = readPositiveInt(dis, "total check blocks");
    this.splitfileType = readSplitfileAlgorithm(dis);
    this.codec = getCodecFor(splitfileType);
    this.dataLength = readPositiveLong(dis, "data length");
    validateDataLengthMatches(dataLength, originalData);
    validateBlockCountCompatibility(dataLength, totalDataBlocks);
    decompressedLength = readPositiveLong(dis, "decompressed length");
    isMetadata = dis.readBoolean();
    archiveType = readArchiveType(dis.readShort());
    clientMetadata = readClientMetadata(dis);
    compressionCodec = readCompressionCodec(dis);
    int segmentCount = readPositiveInt(dis, "segment count");
    this.segmentSize = readPositiveInt(dis, "segment size");
    // Allow zero for NON_REDUNDANT splitfiles (codec == null), where no check blocks exist.
    this.checkSegmentSize = readCheckSegmentSize(dis);
    int ccb = dis.readInt();
    if (ccb < 0) throw new StorageFormatException("Bad cross-check block count");
    this.crossCheckBlocks = ccb;
    validateSegmentTotals(segmentSize, checkSegmentSize, crossCheckBlocks);
    this.splitfileCryptoAlgorithm = dis.readByte();
    validateCryptoAlgorithm(splitfileCryptoAlgorithm);
    splitfileCryptoKey = readOptionalCryptoKey(dis);
    this.keyLength = dis.readInt();
    validateKeyLength(keyLength);
    this.cmode = readCompatibilityModeChecked(dis);
    this.deductBlocksFromSegments = dis.readInt();
    validateDeductBlocksRange(deductBlocksFromSegments, segmentCount);
    this.maxRetries = dis.readInt();
    validateMaxRetries(maxRetries);
    this.consecutiveRNFsCountAsSuccess = dis.readInt();
    if (consecutiveRNFsCountAsSuccess < 0)
      throw new StorageFormatException("Bad consecutiveRNFsCountAsSuccess");
    specifySplitfileKeyInMetadata = dis.readBoolean();
    hashThisLayerOnly = readOptionalHashThisLayerOnly(dis);
    topDontCompress = dis.readBoolean();
    topRequiredBlocks = dis.readInt();
    topTotalBlocks = dis.readInt();
    origDataSize = dis.readLong();
    origCompressedDataSize = dis.readLong();
    hashes = HashResult.readHashes(dis);
    dis.close();
    this.hasPaddedLastBlock = (dataLength % CHKBlock.DATA_LENGTH != 0);
    this.segments = new SplitFileInserterSegmentStorage[segmentCount];
    randomSegmentIterator = new RandomArrayIterator<>(segments);
    this.crossSegments = initCrossSegmentsArrayIfAny(segmentCount);
    // Read offsets.
    is = checker.checksumReaderWithLength(ois, new ArrayBucketFactory(), maxLength);
    dis = new DataInputStream(is);
    OffsetsData od = readOffsets(dis, rafLength, segmentCount);
    dis.close();
    offsetPaddedLastBlock = od.offsetPaddedLastBlock;
    offsetOverallStatus = od.offsetOverallStatus;
    overallStatusLength = od.overallStatusLength;
    offsetCrossSegmentBlocks = od.arrays.offsetCrossSegmentBlocks;
    offsetSegmentCheckBlocks = od.arrays.offsetSegmentCheckBlocks;
    offsetSegmentStatus = od.arrays.offsetSegmentStatus;
    offsetCrossSegmentStatus = od.arrays.offsetCrossSegmentStatus;
    offsetSegmentKeys = od.arrays.offsetSegmentKeys;
    // Set up segments...
    underlyingOffsetDataSegments = new long[segmentCount];
    is = checker.checksumReaderWithLength(ois, new ArrayBucketFactory(), maxLength);
    long blocks = initSegmentsAndComputeBlocks(is, segmentCount, keysFetching);
    if (blocks != totalDataBlocks)
      throw new StorageFormatException(
          "Total data blocks should be " + totalDataBlocks + " but is " + blocks);
    readCrossSegmentsFromDisk(ois, maxLength);
    ois.close();
    errors = readStatusesFromDisk(maxLength);
    computeStatus();

    this.writeMetadataJob = createWriteMetadataJob();
    this.wrapLazyWriteMetadata = () -> jobRunner.queueNormalOrDrop(writeMetadataJob);
  }

  private void computeStatus() {
    status = Status.STARTED;
    if (crossSegments.length != 0) {
      for (SplitFileInserterCrossSegmentStorage segment : crossSegments) {
        if (!segment.isFinishedEncoding()) return;
      }
      status = Status.ENCODED_CROSS_SEGMENTS;
    }
    for (SplitFileInserterSegmentStorage segment : segments) {
      if (!segment.isFinishedEncoding()) return;
    }
    status = Status.ENCODED;
    // Last 3 statuses are only used during completion.
  }

  private long readOffset(DataInputStream dis, long rafLength, String error)
      throws IOException, StorageFormatException {
    long l = dis.readLong();
    if (l < 0) throw new StorageFormatException("Negative " + error);
    if (l > rafLength) throw new StorageFormatException("Too big " + error);
    return l;
  }

  private void writeOverallStatus(boolean force) throws IOException {
    byte[] buf;
    synchronized (this) {
      if (!persistent) return;
      if (!force && !overallStatusDirty) return;
      buf = encodeOverallStatus();
      assert (buf.length == overallStatusLength);
    }
    raf.pwrite(offsetOverallStatus, buf, 0, buf.length);
  }

  private byte[] encodeOverallStatus() {
    //noinspection resource
    ArrayBucket bucket = new ArrayBucket(); // Will be small.
    try {
      try (OutputStream os = bucket.getOutputStream();
          OutputStream cos = checker.checksumWriterWithLength(os, new ArrayBucketFactory());
          DataOutputStream dos = new DataOutputStream(cos)) {
        synchronized (this) {
          errors.writeFixedLengthTo(dos);
          overallStatusDirty = false;
        }
      }
      byte[] out = bucket.toByteArray();
      bucket.free();
      return out;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /** Simple container for segment sizing derived from context and data length. */
  private record SegmentLayout(int segs, int segmentSize, int deductBlocksFromSegments) {}

  private SegmentLayout computeSegmentLayout(
      int totalDataBlocks, InsertContext ctx, CompatibilityMode cmode) {
    int segs =
        (cmode == CompatibilityMode.COMPAT_1250_EXACT)
            ? (totalDataBlocks + 128 - 1) / 128
            : enforceMaxSegmentDataBlocks(
                selectBaseSegments(totalDataBlocks, cmode),
                totalDataBlocks,
                ctx.splitfileSegmentDataBlocks);
    int computedSegmentSize =
        (cmode == CompatibilityMode.COMPAT_1250_EXACT) ? 128 : (totalDataBlocks + segs - 1) / segs;
    int deduct = calculateDeductBlocks(totalDataBlocks, computedSegmentSize, segs, cmode);
    return new SegmentLayout(segs, computedSegmentSize, deduct);
  }

  private int selectBaseSegments(int totalDataBlocks, CompatibilityMode cmode) {
    if (cmode == CompatibilityMode.COMPAT_1251) {
      return (totalDataBlocks + 131 - 1) / 131; // Max 131 blocks per segment.
    }
    if (totalDataBlocks > 520) return (totalDataBlocks + 128 - 1) / 128;
    if (totalDataBlocks > 393) return 4; // maxSegSize = 130
    if (totalDataBlocks > 266) return 3; // maxSegSize = 131
    if (totalDataBlocks > 136) return 2; // maxSegSize = 133
    return 1; // maxSegSize = 136
  }

  private int enforceMaxSegmentDataBlocks(int segs, int totalDataBlocks, int maxBlocksPerSegment) {
    int segSize = (totalDataBlocks + segs - 1) / segs;
    if (maxBlocksPerSegment < segSize) {
      segs = (totalDataBlocks + maxBlocksPerSegment - 1) / maxBlocksPerSegment;
    }
    return segs;
  }

  private int calculateDeductBlocks(
      int totalDataBlocks, int segmentSize, int segs, CompatibilityMode cmode) {
    if (cmode == CompatibilityMode.COMPAT_CURRENT
        || cmode.ordinal() >= CompatibilityMode.COMPAT_1255.ordinal()) {
      int lastSegmentSize = totalDataBlocks - (segmentSize * (segs - 1));
      return segmentSize - lastSegmentSize;
    }
    return 0;
  }

  private int computeCrossCheckBlocks(int segs, CompatibilityMode cmode) {
    // Cross-segment splitfile redundancy becomes useful at 20 segments.
    if (segs >= 20
        && (cmode == CompatibilityMode.COMPAT_CURRENT
            || cmode.ordinal() >= CompatibilityMode.COMPAT_1255.ordinal())) {
      return 3; // Optimal number of cross-check blocks per segment
    }
    return 0;
  }

  private SplitFileInserterCrossSegmentStorage[] initCrossSegmentsIfAny(
      int segs, int crossCheckBlocks, int segmentSize, int deductBlocksFromSegments) {
    if (crossCheckBlocks == 0) return new SplitFileInserterCrossSegmentStorage[0];
    byte[] seed = Metadata.getCrossSegmentSeed(hashes, hashThisLayerOnly);
    if (LOG.isDebugEnabled()) LOG.debug("Cross-segment seed: {}", HexUtil.bytesToHex(seed));
    Random xsRandom = MersenneTwister.createUnsynchronized(seed);
    SplitFileInserterCrossSegmentStorage[] xs = new SplitFileInserterCrossSegmentStorage[segs];
    int segLen = segmentSize;
    for (int i = 0; i < xs.length; i++) {
      if (LOG.isDebugEnabled()) LOG.debug("Allocating blocks for cross segment {}", i);
      if (segments.length - i == deductBlocksFromSegments) {
        segLen--;
      }
      SplitFileInserterCrossSegmentStorage seg =
          new SplitFileInserterCrossSegmentStorage(this, i, persistent, segLen, crossCheckBlocks);
      xs[i] = seg;
      for (int j = 0; j < segLen; j++) allocateCrossDataBlock(seg, xsRandom);
      for (int j = 0; j < crossCheckBlocks; j++) allocateCrossCheckBlock(seg, xsRandom);
    }
    return xs;
  }

  private Bucket encodeSegmentSettings() {
    ArrayBucket bucket = new ArrayBucket(); // Will be small.
    try {
      try (OutputStream os = bucket.getOutputStream();
          OutputStream cos = checker.checksumWriterWithLength(os, new ArrayBucketFactory());
          DataOutputStream dos = new DataOutputStream(cos)) {
        for (SplitFileInserterSegmentStorage segment : segments) {
          segment.writeFixedSettings(dos);
        }
      }
      return bucket;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /**
   * This one could actually be rather large, since it includes the listing of which blocks go in
   * which cross-segments ...
   */
  private Bucket encodeCrossSegmentSettings(BucketFactory bf) throws IOException {
    if (crossSegments.length == 0) return new NullBucket();
    Bucket bucket = bf.makeBucket(-1);
    try (OutputStream os = bucket.getOutputStream();
        OutputStream cos = checker.checksumWriterWithLength(os, new ArrayBucketFactory());
        DataOutputStream dos = new DataOutputStream(cos)) {
      for (SplitFileInserterCrossSegmentStorage segment : crossSegments) {
        segment.writeFixedSettings(dos);
      }
    }
    return bucket;
  }

  /** Includes magic, version, length, basic settings, checksum. */
  private byte[] encodeHeader() {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    try {
      dos.writeLong(MAGIC);
      dos.writeInt(checker.getChecksumTypeID());
      OutputStream os = checker.checksumWriterWithLength(baos, new ArrayBucketFactory());
      dos = new DataOutputStream(os);
      dos.writeInt(VERSION);
      originalData.storeTo(dos);
      dos.writeInt(totalDataBlocks);
      dos.writeInt(totalCheckBlocks);
      dos.writeShort(splitfileType.code); // And hence the FECCodec
      dos.writeLong(dataLength);
      dos.writeLong(decompressedLength);
      dos.writeBoolean(isMetadata);
      if (archiveType == null) dos.writeShort((short) -1);
      else dos.writeShort(archiveType.metadataID);
      clientMetadata.writeTo(dos);
      if (compressionCodec == null) dos.writeShort((short) -1);
      else dos.writeShort(compressionCodec.metadataID);
      dos.writeInt(segments.length);
      dos.writeInt(segmentSize);
      dos.writeInt(checkSegmentSize);
      dos.writeInt(crossCheckBlocks);
      dos.writeByte(this.splitfileCryptoAlgorithm);
      dos.writeBoolean(this.splitfileCryptoKey != null);
      if (this.splitfileCryptoKey != null) {
        assert (splitfileCryptoKey.length == 32);
        dos.write(splitfileCryptoKey);
      }
      dos.writeInt(keyLength);
      dos.writeInt(cmode.ordinal());
      // hasPaddedLastBlock will be recomputed.
      dos.writeInt(deductBlocksFromSegments);
      dos.writeInt(maxRetries);
      dos.writeInt(consecutiveRNFsCountAsSuccess);
      dos.writeBoolean(specifySplitfileKeyInMetadata);
      dos.writeBoolean(hashThisLayerOnly != null);
      if (hashThisLayerOnly != null) {
        assert (hashThisLayerOnly.length == 32);
        dos.write(hashThisLayerOnly);
      }
      // Top level stuff
      dos.writeBoolean(topDontCompress);
      dos.writeInt(topRequiredBlocks);
      dos.writeInt(topTotalBlocks);
      dos.writeLong(origDataSize);
      dos.writeLong(origCompressedDataSize);
      HashResult.write(hashes, dos);
      dos.close();
      return baos.toByteArray();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /** Encode the offsets. */
  private byte[] encodeOffsets() {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try {
      OutputStream os = checker.checksumWriterWithLength(baos, new ArrayBucketFactory());
      DataOutputStream dos = new DataOutputStream(os);
      if (this.hasPaddedLastBlock) dos.writeLong(offsetPaddedLastBlock);
      dos.writeLong(offsetOverallStatus);
      dos.writeInt(overallStatusLength);
      if (crossSegments.length != 0) {
        for (long l : offsetCrossSegmentBlocks) dos.writeLong(l);
      }
      for (long l : offsetSegmentCheckBlocks) dos.writeLong(l);
      for (long l : offsetSegmentStatus) dos.writeLong(l);
      if (crossSegments.length != 0) {
        for (long l : offsetCrossSegmentStatus) dos.writeLong(l);
      }
      for (long l : offsetSegmentKeys) dos.writeLong(l);
      dos.close();
      return baos.toByteArray();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private record DataCheck(int data, int check) {}

  private int readCheckSegmentSize(DataInputStream dis) throws IOException, StorageFormatException {
    int v = dis.readInt();
    if (v < 0) throw new StorageFormatException("Bad check segment size " + v);
    return v;
  }

  private int clampToDataBlocks(int i, int dataBlocks) {
    return Math.min(i, dataBlocks);
  }

  private DataCheck adjustForLastSegmentIfNeeded(
      int data, int check, int i, int j, int segNo, int segCount) {
    if (data > (i - j)) {
      assert (segNo == segCount - 1);
      data = i - j;
      check = (codec != null) ? codec.getCheckBlocks(data + crossCheckBlocks, cmode) : 0;
    }
    return new DataCheck(data, check);
  }

  private int maybeDeductBlock(int data, int segCount, int segNo, int deductBlocksFromSegments) {
    if (segCount - segNo == deductBlocksFromSegments) {
      return data - 1;
    }
    return data;
  }

  private void validateMagic(long magic) throws StorageFormatException {
    if (magic != MAGIC) throw new StorageFormatException("Bad magic");
  }

  private void validateVersion(int version) throws StorageFormatException {
    if (version != VERSION) throw new StorageFormatException("Bad version");
  }

  @SuppressWarnings("java:S1168")
  private byte[] readOptionalCryptoKey(DataInputStream dis) throws IOException {
    if (dis.readBoolean()) {
      byte[] key = new byte[32];
      dis.readFully(key);
      return key;
    }
    return null;
  }

  private CompatibilityMode readCompatibilityModeChecked(DataInputStream dis)
      throws IOException, StorageFormatException {
    int compatMode = dis.readInt();
    if (compatMode < 0 || compatMode > CompatibilityMode.values().length)
      throw new StorageFormatException("Invalid compatibility mode " + compatMode);
    return CompatibilityMode.values()[compatMode];
  }

  @SuppressWarnings("java:S1168")
  private byte[] readOptionalHashThisLayerOnly(DataInputStream dis) throws IOException {
    if (dis.readBoolean()) {
      byte[] h = new byte[32];
      dis.readFully(h);
      return h;
    }
    return null;
  }

  private SplitFileInserterCrossSegmentStorage[] initCrossSegmentsArrayIfAny(int segmentCount) {
    return (crossCheckBlocks != 0)
        ? new SplitFileInserterCrossSegmentStorage[segmentCount]
        : new SplitFileInserterCrossSegmentStorage[0];
  }

  private record OffsetsData(
      long offsetPaddedLastBlock,
      long offsetOverallStatus,
      int overallStatusLength,
      OffsetArrays arrays) {}

  private OffsetsData readOffsets(DataInputStream dis, long rafLength, int segmentCount)
      throws IOException, StorageFormatException {
    long offsetPaddedLastBlockLocal = 0;
    if (hasPaddedLastBlock) {
      offsetPaddedLastBlockLocal = readOffset(dis, rafLength, "offsetPaddedLastBlock");
    }
    long offsetOverallStatusLocal = readOffset(dis, rafLength, "offsetOverallStatus");
    int overallStatusLengthLocal = dis.readInt();
    if (overallStatusLengthLocal < 0)
      throw new StorageFormatException("Negative overall status length");
    if (overallStatusLengthLocal < FailureCodeTracker.getFixedLength(true))
      throw new StorageFormatException("Bad overall status length");
    long[] offsetCrossSegmentBlocksLocal = null;
    long[] offsetCrossSegmentStatusLocal = null;
    if (crossSegments.length != 0) {
      offsetCrossSegmentBlocksLocal = new long[crossSegments.length];
      for (int i = 0; i < crossSegments.length; i++)
        offsetCrossSegmentBlocksLocal[i] = readOffset(dis, rafLength, "cross-segment block offset");
    }
    long[] offsetSegmentCheckBlocksLocal = new long[segmentCount];
    for (int i = 0; i < segmentCount; i++)
      offsetSegmentCheckBlocksLocal[i] = readOffset(dis, rafLength, "segment check block offset");
    long[] offsetSegmentStatusLocal = new long[segmentCount];
    for (int i = 0; i < segmentCount; i++)
      offsetSegmentStatusLocal[i] = readOffset(dis, rafLength, "segment status offset");
    if (crossSegments.length != 0) {
      offsetCrossSegmentStatusLocal = new long[crossSegments.length];
      for (int i = 0; i < crossSegments.length; i++)
        offsetCrossSegmentStatusLocal[i] =
            readOffset(dis, rafLength, "cross-segment status offset");
    }
    long[] offsetSegmentKeysLocal = new long[segmentCount];
    for (int i = 0; i < segmentCount; i++)
      offsetSegmentKeysLocal[i] = readOffset(dis, rafLength, "segment keys offset");
    OffsetArrays arrays =
        new OffsetArrays(
            offsetCrossSegmentBlocksLocal,
            offsetSegmentCheckBlocksLocal,
            offsetSegmentStatusLocal,
            offsetCrossSegmentStatusLocal,
            offsetSegmentKeysLocal);
    return new OffsetsData(
        offsetPaddedLastBlockLocal, offsetOverallStatusLocal, overallStatusLengthLocal, arrays);
  }

  private long initSegmentsAndComputeBlocks(
      InputStream is, int segmentCount, KeysFetchingLocally keysFetching)
      throws IOException, StorageFormatException {
    DataInputStream dis = new DataInputStream(is);
    long blocks = 0;
    for (int i = 0; i < segmentCount; i++) {
      segments[i] =
          new SplitFileInserterSegmentStorage(
              this,
              dis,
              i,
              new SplitFileInserterSegmentStorage.Params()
                  .keys(keyLength, splitfileCryptoAlgorithm, splitfileCryptoKey)
                  .codec(random, maxRetries, consecutiveRNFsCountAsSuccess, keysFetching));
      underlyingOffsetDataSegments[i] = blocks * CHKBlock.DATA_LENGTH;
      blocks += segments[i].dataBlockCount;
      assert (underlyingOffsetDataSegments[i] < dataLength);
    }
    dis.close();
    return blocks;
  }

  private void readCrossSegmentsFromDisk(InputStream ois, long maxLength)
      throws IOException, ChecksumFailedException, StorageFormatException {
    // When there are no cross-check blocks we do not write any cross-segment
    // settings section, so skip attempting to read it on resume.
    if (crossSegments.length == 0) return;
    InputStream is = checker.checksumReaderWithLength(ois, new ArrayBucketFactory(), maxLength);
    DataInputStream dis = new DataInputStream(is);
    for (int i = 0; i < crossSegments.length; i++) {
      crossSegments[i] = new SplitFileInserterCrossSegmentStorage(this, dis, i);
    }
    dis.close();
  }

  private FailureCodeTracker readStatusesFromDisk(long maxLength)
      throws IOException, StorageFormatException, ChecksumFailedException {
    InputStream ois = new RAFInputStream(raf, offsetOverallStatus, rafLength - offsetOverallStatus);
    DataInputStream dis =
        new DataInputStream(
            checker.checksumReaderWithLength(ois, new ArrayBucketFactory(), maxLength));
    FailureCodeTracker tracker = new FailureCodeTracker(true, dis);
    dis.close();
    for (SplitFileInserterSegmentStorage segment : segments) {
      segment.readStatus();
    }
    for (SplitFileInserterCrossSegmentStorage segment : crossSegments) {
      segment.readStatus();
    }
    return tracker;
  }

  private int readPositiveInt(DataInputStream dis, String name)
      throws IOException, StorageFormatException {
    int v = dis.readInt();
    if (v <= 0) throw new StorageFormatException("Bad " + name + " " + v);
    return v;
  }

  // Non-negative int reads are handled inline at call sites to ensure precise error messages.

  private long readPositiveLong(DataInputStream dis, String name)
      throws IOException, StorageFormatException {
    long v = dis.readLong();
    if (v <= 0) throw new StorageFormatException("Bad " + name);
    return v;
  }

  private void validateDataLengthMatches(long dataLength, LockableRandomAccessBuffer originalData)
      throws ResumeFailedException {
    if (dataLength != originalData.size())
      throw new ResumeFailedException(
          "Original data size is " + originalData.size() + " should be " + dataLength);
  }

  private void validateBlockCountCompatibility(long dataLength, int totalDataBlocks)
      throws StorageFormatException {
    if (((dataLength + CHKBlock.DATA_LENGTH - 1) / CHKBlock.DATA_LENGTH) != totalDataBlocks)
      throw new StorageFormatException(
          "Data blocks " + totalDataBlocks + " not compatible with size " + dataLength);
  }

  private void validateSegmentTotals(int segmentSize, int checkSegmentSize, int crossCheckBlocks)
      throws StorageFormatException {
    if (segmentSize + checkSegmentSize + crossCheckBlocks > FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT)
      throw new StorageFormatException(
          "Must be no more than " + FECCodec.MAX_TOTAL_BLOCKS_PER_SEGMENT + " blocks per segment");
  }

  private void validateCryptoAlgorithm(byte algo) throws StorageFormatException {
    if (!Metadata.isValidSplitfileCryptoAlgorithm(algo))
      throw new StorageFormatException("Invalid splitfile crypto algorithm " + algo);
  }

  private void validateKeyLength(int keyLength) throws StorageFormatException {
    int min = SplitFileInserterSegmentStorage.getKeyLength(this);
    if (keyLength < min)
      throw new StorageFormatException(
          "Invalid key length " + keyLength + " should be at least " + min);
  }

  private void validateDeductBlocksRange(int value, int segmentCount)
      throws StorageFormatException {
    if (value < 0 || value > segmentCount)
      throw new StorageFormatException("Bad deductBlocksFromSegments");
  }

  private void validateMaxRetries(int value) throws StorageFormatException {
    if (value < -1) throw new StorageFormatException("Bad maxRetries");
  }

  // Removed validateNonNegative(): inlined at call site for clarity

  private ChecksumChecker createChecksumChecker(int checksumType) throws StorageFormatException {
    try {
      return ChecksumChecker.create(checksumType);
    } catch (IllegalArgumentException e) {
      throw new StorageFormatException("Bad checksum type");
    }
  }

  private SplitfileAlgorithm readSplitfileAlgorithm(DataInputStream dis)
      throws IOException, StorageFormatException {
    try {
      return SplitfileAlgorithm.getByCode(dis.readShort());
    } catch (IllegalArgumentException e) {
      throw new StorageFormatException("Bad splitfile type");
    }
  }

  private FECCodec getCodecFor(SplitfileAlgorithm algorithm) throws StorageFormatException {
    try {
      return FECCodec.getInstance(algorithm);
    } catch (IllegalArgumentException e) {
      throw new StorageFormatException("Bad splitfile codec type");
    }
  }

  private ARCHIVE_TYPE readArchiveType(short atype) throws StorageFormatException {
    if (atype == -1) return null;
    ARCHIVE_TYPE t = ARCHIVE_TYPE.getArchiveType(atype);
    if (t == null) throw new StorageFormatException("Unknown archive type " + atype);
    return t;
  }

  private ClientMetadata readClientMetadata(DataInputStream dis)
      throws IOException, StorageFormatException {
    try {
      return ClientMetadata.construct(dis);
    } catch (MetadataParseException e) {
      throw new StorageFormatException("Failed to read MIME type: " + e);
    }
  }

  private COMPRESSOR_TYPE readCompressionCodec(DataInputStream dis)
      throws IOException, StorageFormatException {
    short c = dis.readShort();
    if (c == (short) -1) return null;
    COMPRESSOR_TYPE cc = COMPRESSOR_TYPE.getCompressorByMetadataID(c);
    if (cc == null) throw new StorageFormatException("Unknown compression codec ID " + c);
    return cc;
  }

  private LockableRandomAccessBuffer chooseOriginalData(
      LockableRandomAccessBuffer passed, LockableRandomAccessBuffer restored)
      throws StorageFormatException {
    if (passed == null) return restored;
    if (!passed.equals(restored))
      throw new StorageFormatException(
          "Original data restored from different filename! Expected "
              + passed
              + " but restored "
              + restored);
    return passed;
  }

  private static final class CryptoInit {
    final byte[] key;
    final boolean specifyInMetadata;

    CryptoInit(byte[] key, boolean specifyInMetadata) {
      this.key = key;
      this.specifyInMetadata = specifyInMetadata;
    }
  }

  private CryptoInit chooseSplitfileKey(
      byte[] providedKey, CompatibilityMode cmode, byte[] hashThisLayerOnly, HashResult[] hashes) {
    if (providedKey != null) {
      return new CryptoInit(providedKey, true);
    } else if (cmode == CompatibilityMode.COMPAT_CURRENT
        || cmode.ordinal() >= CompatibilityMode.COMPAT_1255.ordinal()) {
      byte[] key =
          (hashThisLayerOnly != null)
              ? Metadata.getCryptoKey(hashThisLayerOnly)
              : Metadata.getCryptoKey(hashes);
      return new CryptoInit(key, false);
    } else {
      return new CryptoInit(null, false);
    }
  }

  private static long padTo4096(long value) {
    int padding = (int) (value % 4096);
    return padding == 0 ? value : value + (4096 - padding);
  }

  private long calculateInitialPtr(
      byte[] header, int offsetsLength, Bucket segmentSettings, Bucket crossSegmentSettings) {
    return header.length
        + offsetsLength
        + segmentSettings.size()
        + (crossSegmentSettings == null ? 0 : crossSegmentSettings.size());
  }

  private static final class OffsetArrays {
    final long[] offsetCrossSegmentBlocks;
    final long[] offsetSegmentCheckBlocks;
    final long[] offsetSegmentStatus;
    final long[] offsetCrossSegmentStatus;
    final long[] offsetSegmentKeys;

    OffsetArrays(
        long[] offsetCrossSegmentBlocks,
        long[] offsetSegmentCheckBlocks,
        long[] offsetSegmentStatus,
        long[] offsetCrossSegmentStatus,
        long[] offsetSegmentKeys) {
      this.offsetCrossSegmentBlocks = offsetCrossSegmentBlocks;
      this.offsetSegmentCheckBlocks = offsetSegmentCheckBlocks;
      this.offsetSegmentStatus = offsetSegmentStatus;
      this.offsetCrossSegmentStatus = offsetCrossSegmentStatus;
      this.offsetSegmentKeys = offsetSegmentKeys;
    }
  }

  private OffsetArrays createOffsetArrays(boolean persistent) {
    long[] ocb = (crossSegments.length != 0) ? new long[crossSegments.length] : null;
    long[] ocs = (crossSegments.length != 0 && persistent) ? new long[crossSegments.length] : null;
    long[] osc = new long[segments.length];
    long[] oss = persistent ? new long[segments.length] : null;
    long[] osk = new long[segments.length];
    return new OffsetArrays(ocb, osc, oss, ocs, osk);
  }

  private static final class PersistenceInit {
    final byte[] header;
    final int offsetsLength;
    final Bucket segmentSettings;
    final Bucket crossSegmentSettings;

    PersistenceInit(
        byte[] header, int offsetsLength, Bucket segmentSettings, Bucket crossSegmentSettings) {
      this.header = header;
      this.offsetsLength = offsetsLength;
      this.segmentSettings = segmentSettings;
      this.crossSegmentSettings = crossSegmentSettings;
    }
  }

  private PersistenceInit preparePersistenceInit(BucketFactory bf) throws InsertException {
    byte[] header = encodeHeader();
    int offsetsLength = encodeOffsets().length;
    Bucket segmentSettings = encodeSegmentSettings();
    Bucket crossSegmentSettings;
    try {
      crossSegmentSettings = encodeCrossSegmentSettings(bf);
    } catch (IOException e) {
      throw new InsertException(
          InsertExceptionMode.BUCKET_ERROR,
          "Failed to write to temporary storage while creating splitfile inserter",
          null);
    }
    return new PersistenceInit(header, offsetsLength, segmentSettings, crossSegmentSettings);
  }

  private long populateCrossSegmentOffsets(long ptr) {
    if (crossSegments.length == 0) return ptr;
    for (int i = 0; i < crossSegments.length; i++) {
      offsetCrossSegmentBlocks[i] = ptr;
      ptr += (long) crossSegments[i].crossCheckBlockCount * CHKBlock.DATA_LENGTH;
    }
    return ptr;
  }

  private long populateSegmentCheckOffsets(long ptr) {
    for (int i = 0; i < segments.length; i++) {
      offsetSegmentCheckBlocks[i] = ptr;
      ptr += (long) segments[i].checkBlockCount * CHKBlock.DATA_LENGTH;
    }
    return ptr;
  }

  private long populateSegmentStatusOffsets(long ptr) {
    for (int i = 0; i < segments.length; i++) {
      offsetSegmentStatus[i] = ptr;
      ptr += segments[i].storedStatusLength();
    }
    return ptr;
  }

  private long populateCrossSegmentStatusOffsets(long ptr) {
    if (crossSegments.length == 0) return ptr;
    for (int i = 0; i < crossSegments.length; i++) {
      offsetCrossSegmentStatus[i] = ptr;
      ptr += crossSegments[i].storedStatusLength();
    }
    return ptr;
  }

  private long populateStatusOffsetsIfPersistent(long ptr) {
    if (!persistent) return ptr;
    ptr = populateSegmentStatusOffsets(ptr);
    return populateCrossSegmentStatusOffsets(ptr);
  }

  private void writeInitialRafIfPersistent(
      byte[] header, int offsetsLength, Bucket segmentSettings, Bucket crossSegmentSettings)
      throws IOException {
    if (!persistent) return;
    writeInitialRaf(header, offsetsLength, segmentSettings, crossSegmentSettings);
  }

  private void writePaddedLastBlockIfAny(byte[] paddedLastBlock) throws IOException {
    if (hasPaddedLastBlock)
      raf.pwrite(offsetPaddedLastBlock, paddedLastBlock, 0, paddedLastBlock.length);
  }

  private void clearInitialStatusesIfPersistent() {
    if (!persistent) return;
    clearInitialStatuses();
  }

  private long populateSegmentKeyOffsets(long ptr) {
    for (int i = 0; i < segments.length; i++) {
      offsetSegmentKeys[i] = ptr;
      ptr += segments[i].storedKeysLength();
    }
    return ptr;
  }

  private void writeInitialRaf(
      byte[] header, int offsetsLength, Bucket segmentSettings, Bucket crossSegmentSettings)
      throws IOException {
    long ptr = 0;
    raf.pwrite(ptr, header, 0, header.length);
    ptr += header.length;
    byte[] encodedOffsets = encodeOffsets();
    assert (encodedOffsets.length == offsetsLength);
    raf.pwrite(ptr, encodedOffsets, 0, encodedOffsets.length);
    ptr += encodedOffsets.length;
    BucketTools.copyTo(segmentSettings, raf, ptr, Long.MAX_VALUE);
    ptr += segmentSettings.size();
    segmentSettings.free();
    if (crossSegmentSettings != null) {
      BucketTools.copyTo(crossSegmentSettings, raf, ptr, Long.MAX_VALUE);
      crossSegmentSettings.free();
    }
    writeOverallStatus(true);
  }

  private void clearInitialStatuses() {
    // Padding is initialized to random already.
    for (SplitFileInserterSegmentStorage segment : segments) {
      if (LOG.isDebugEnabled()) LOG.debug("Clearing status for {}", segment);
      segment.storeStatus(true);
    }
    if (crossSegments != null) {
      for (SplitFileInserterCrossSegmentStorage segment : crossSegments) {
        if (LOG.isDebugEnabled()) LOG.debug("Clearing status for {}", segment);
        segment.storeStatus();
      }
    }
  }

  private void allocateCrossDataBlock(
      SplitFileInserterCrossSegmentStorage segment, Random xsRandom) {
    int x = 0;
    for (int i = 0; i < 10; i++) {
      x = xsRandom.nextInt(segments.length);
      SplitFileInserterSegmentStorage seg = segments[x];
      int blockNum = seg.allocateCrossDataBlock(xsRandom);
      if (blockNum >= 0) {
        segment.addDataBlock(seg, blockNum);
        return;
      }
    }
    for (int i = 0; i < segments.length; i++) {
      x++;
      if (x == segments.length) x = 0;
      SplitFileInserterSegmentStorage seg = segments[x];
      int blockNum = seg.allocateCrossDataBlock(xsRandom);
      if (blockNum >= 0) {
        segment.addDataBlock(seg, blockNum);
        return;
      }
    }
    throw new IllegalStateException("Unable to allocate cross data block!");
  }

  private void allocateCrossCheckBlock(
      SplitFileInserterCrossSegmentStorage segment, Random xsRandom) {
    int x = 0;
    for (int i = 0; i < 10; i++) {
      x = xsRandom.nextInt(segments.length);
      SplitFileInserterSegmentStorage seg = segments[x];
      int blockNum =
          seg.allocateCrossCheckBlock(segment, xsRandom, segment.getAllocatedCrossCheckBlocks());
      if (blockNum >= 0) {
        segment.addCheckBlock(seg, blockNum);
        return;
      }
    }
    for (int i = 0; i < segments.length; i++) {
      x++;
      if (x == segments.length) x = 0;
      SplitFileInserterSegmentStorage seg = segments[x];
      int blockNum =
          seg.allocateCrossCheckBlock(segment, xsRandom, segment.getAllocatedCrossCheckBlocks());
      if (blockNum >= 0) {
        segment.addCheckBlock(seg, blockNum);
        return;
      }
    }
    throw new IllegalStateException("Unable to allocate cross data block!");
  }

  private SplitFileInserterSegmentStorage[] makeSegments(
      int segmentSize,
      int segCount,
      int dataBlocks,
      int deductBlocksFromSegments,
      KeysFetchingLocally keysFetching,
      int consecutiveRNFsCountAsSuccess) {
    SplitFileInserterSegmentStorage[] segArr = new SplitFileInserterSegmentStorage[segCount];
    if (segCount == 1) {
      initSingleSegment(segArr, dataBlocks, keysFetching, consecutiveRNFsCountAsSuccess);
    } else {
      populateMultiSegments(
          segArr,
          segmentSize,
          segCount,
          dataBlocks,
          deductBlocksFromSegments,
          keysFetching,
          consecutiveRNFsCountAsSuccess);
    }
    return segArr;
  }

  private void initSingleSegment(
      SplitFileInserterSegmentStorage[] segArr,
      int dataBlocks,
      KeysFetchingLocally keysFetching,
      int consecutiveRNFsCountAsSuccess) {
    int checkBlocks =
        (codec != null) ? codec.getCheckBlocks(dataBlocks + crossCheckBlocks, cmode) : 0;
    segArr[0] =
        new SplitFileInserterSegmentStorage(
            this,
            0,
            new SplitFileInserterSegmentStorage.Params()
                .blocks(dataBlocks, checkBlocks, crossCheckBlocks)
                .keys(keyLength, splitfileCryptoAlgorithm, splitfileCryptoKey)
                .codec(random, maxRetries, consecutiveRNFsCountAsSuccess, keysFetching));
  }

  private void populateMultiSegments(
      SplitFileInserterSegmentStorage[] segArr,
      int segmentSize,
      int segCount,
      int dataBlocks,
      int deductBlocksFromSegments,
      KeysFetchingLocally keysFetching,
      int consecutiveRNFsCountAsSuccess) {
    int j = 0;
    int segNo = 0;
    int data = segmentSize;
    int check = (codec != null) ? codec.getCheckBlocks(data + crossCheckBlocks, cmode) : 0;
    int i = segmentSize;
    while (true) {
      this.underlyingOffsetDataSegments[segNo] = (long) j * CHKBlock.DATA_LENGTH;
      i = clampToDataBlocks(i, dataBlocks);
      DataCheck dc = adjustForLastSegmentIfNeeded(data, check, i, j, segNo, segCount);
      data = dc.data;
      check = dc.check;
      j = i;
      segArr[segNo] =
          new SplitFileInserterSegmentStorage(
              this,
              segNo,
              new SplitFileInserterSegmentStorage.Params()
                  .blocks(data, check, crossCheckBlocks)
                  .keys(keyLength, splitfileCryptoAlgorithm, splitfileCryptoKey)
                  .codec(random, maxRetries, consecutiveRNFsCountAsSuccess, keysFetching));

      if (deductBlocksFromSegments != 0 && LOG.isDebugEnabled())
        LOG.debug(
            "INSERTING: Segment {} of {} : {} data blocks {} check blocks",
            segNo,
            segCount,
            data,
            check);

      segNo++;
      if (i == dataBlocks) break;
      // Deduct one block from each later segment, rather than having
      // a really short last segment.
      data = maybeDeductBlock(data, segCount, segNo, deductBlocksFromSegments);
      i += data;
    }
    assert (segNo == segCount);
  }

  /**
   * Starts encoding work for this storage instance.
   *
   * <p>If cross-segment redundancy was configured, begins by encoding cross-segments and only then
   * starts per-segment encoding. Otherwise, starts segment encoding immediately. This method is
   * idempotent with respect to internal state and returns quickly when encoding has already
   * completed or the storage has failed.
   */
  public void start() {
    boolean startSegments = (crossSegments.length == 0);
    synchronized (this) {
      if (status == Status.NOT_STARTED) {
        status = Status.STARTED;
      }
      if (status == Status.ENCODED_CROSS_SEGMENTS) startSegments = true;
      if (status == Status.ENCODED) return;
      if (status == Status.FAILED
          || status == Status.GENERATING_METADATA
          || status == Status.SUCCEEDED) return;
    }
    for (SplitFileInserterSegmentStorage segment : segments) segment.checkKeys();
    LOG.info(
        "Starting splitfile, {}/{} segments encoded on {}",
        countEncodedSegments(),
        segments.length,
        this);
    if (crossSegments.length != 0)
      LOG.info(
          "Starting splitfile, {}/{} cross-segments encoded on {}",
          countEncodedCrossSegments(),
          crossSegments.length,
          this);
    if (startSegments) {
      startSegmentEncode();
    } else {
      // Cross-segment encode must complete before main encode.
      startCrossSegmentEncode();
    }
  }

  /**
   * Returns the number of segments that have completed encoding.
   *
   * @return count of segments whose check blocks have been fully generated and stored.
   */
  public int countEncodedSegments() {
    int total = 0;
    for (SplitFileInserterSegmentStorage segment : segments) {
      if (segment.hasEncoded()) total++;
    }
    return total;
  }

  /**
   * Returns the number of cross-segments that have completed encoding.
   *
   * @return count of cross-segment encoders that reported completion.
   */
  public int countEncodedCrossSegments() {
    int total = 0;
    for (SplitFileInserterCrossSegmentStorage segment : crossSegments) {
      if (segment.isFinishedEncoding()) total++;
    }
    return total;
  }

  private void startSegmentEncode() {
    short prio = callback.getPriorityClass();
    for (SplitFileInserterSegmentStorage segment : segments) segment.startEncode(prio);
  }

  private void startCrossSegmentEncode() {
    short prio = callback.getPriorityClass();
    // Start cross-segment encode.
    for (SplitFileInserterCrossSegmentStorage segment : crossSegments) segment.startEncode(prio);
  }

  /**
   * Notifies the storage that a cross-segment finished encoding.
   *
   * <p>The completion is processed asynchronously on the persistent job runner to minimize lock
   * contention. When all cross-segments have finished, the storage transitions to {@code
   * ENCODED_CROSS_SEGMENTS} and starts the main segment encoding phase.
   *
   * @param completed the cross-segment that completed encoding; used for logging and diagnostics.
   */
  public void onFinishedEncoding(SplitFileInserterCrossSegmentStorage completed) {
    if (LOG.isDebugEnabled()) LOG.debug("Cross-segment finished encoding: {}", completed);
    jobRunner.queueNormalOrDrop(
        context -> {
          synchronized (cooldownLock) {
            noBlocksToSend = false;
          }
          callback.encodingProgress();
          if (maybeFail()) return true;
          if (allFinishedCrossEncoding()) {
            onCompletedCrossSegmentEncode();
          }
          return false;
        });
  }

  private boolean allFinishedCrossEncoding() {
    for (SplitFileInserterCrossSegmentStorage segment : crossSegments) {
      if (!segment.isFinishedEncoding()) return false;
    }
    return true;
  }

  /**
   * Notifies the storage that a segment finished encoding.
   *
   * <p>The storage persists the segment status, updates progress, and when every segment has
   * finished encoding transitions to the completion path to produce metadata and notify success.
   * Processing occurs asynchronously via the job runner.
   *
   * @param completed the segment that completed encoding; used to persist status and progress.
   */
  public void onFinishedEncoding(final SplitFileInserterSegmentStorage completed) {
    jobRunner.queueNormalOrDrop(
        context -> {
          synchronized (cooldownLock) {
            noBlocksToSend = false;
          }
          completed.storeStatus(true);
          callback.encodingProgress();
          if (maybeFail()) return true;
          if (allFinishedEncoding()) {
            onCompletedSegmentEncode();
          }
          return false;
        });
  }

  private boolean allFinishedEncoding() {
    for (SplitFileInserterSegmentStorage segment : segments) {
      if (!segment.isFinishedEncoding()) return false;
    }
    return true;
  }

  /** Called when we have completed encoding all the cross-segments */
  private void onCompletedCrossSegmentEncode() {
    synchronized (this) {
      if (status == Status.ENCODED_CROSS_SEGMENTS) return; // Race condition.
      if (status != Status.STARTED) {
        LOG.error("Wrong state {} for {}", status, this);
        return;
      }
      status = Status.ENCODED_CROSS_SEGMENTS;
    }
    startSegmentEncode();
  }

  private void onCompletedSegmentEncode() {
    synchronized (this) {
      if (status == Status.ENCODED) return; // Race condition.
      if (!(status == Status.ENCODED_CROSS_SEGMENTS
          || (crossSegments.length == 0 && status == Status.STARTED))) {
        LOG.error("Wrong state {} for {}", status, this);
        return;
      }
      status = Status.ENCODED;
    }
    callback.onFinishedEncode();
  }

  /**
   * Notifies that a segment obtained keys for all of its blocks.
   *
   * <p>When every segment reports it has keys, delegates to {@code onHasKeys()} to inform the
   * callback that metadata can be emitted early (depending on configuration).
   *
   * @param splitFileInserterSegmentStorage the reporting segment instance; used for logging only.
   */
  public void onHasKeys(SplitFileInserterSegmentStorage splitFileInserterSegmentStorage) {
    if (LOG.isDebugEnabled())
      LOG.debug("onHasKeys called from {}", splitFileInserterSegmentStorage);
    for (SplitFileInserterSegmentStorage segment : segments) {
      if (!segment.hasKeys()) return;
    }
    onHasKeys();
  }

  /** Called when we have keys for every block. */
  private void onHasKeys() {
    callback.onHasKeys();
  }

  /**
   * Create an OutputStream that we can write formatted data to of a specific length. On close(), it
   * checks that the length is as expected, computes the checksum, and writes the data to the
   * specified position in the file.
   *
   * @param fileOffset The position in the file (raf) of the first byte.
   * @param length The length, including checksum, of the data to be written.
   * @return
   */
  OutputStream writeChecksummedTo(final long fileOffset, final int length) {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream(length);
    OutputStream cos = checker.checksumWriter(baos);
    return new FilterOutputStream(cos) {

      @Override
      public void close() throws IOException {
        out.close();
        byte[] buf = baos.toByteArray();
        if (buf.length != length)
          throw new IllegalStateException(
              "Wrote wrong number of bytes: " + buf.length + " should be " + length);
        raf.pwrite(fileOffset, buf, 0, length);
      }
    };
  }

  long segmentStatusOffset(int segNo) {
    return offsetSegmentStatus[segNo];
  }

  long crossSegmentStatusOffset(int segNo) {
    return offsetCrossSegmentStatus[segNo];
  }

  static final long MAGIC = 0x4d2a3f596bbf5de5L;
  static final int VERSION = 1;

  /**
   * Indicates whether a splitfile encryption key is present.
   *
   * @return {@code true} when a 32-byte splitfile key is stored for this insert; otherwise {@code
   *     false} when the key is implicit or not required.
   */
  public boolean hasSplitfileKey() {
    return splitfileCryptoKey != null;
  }

  /**
   * Write a cross-check block to disk
   *
   * @throws IOException
   */
  void writeCheckBlock(int segNo, int checkBlockNo, byte[] buf) throws IOException {
    synchronized (this) {
      if (status == Status.ENCODED || status == Status.ENCODED_CROSS_SEGMENTS)
        throw new IllegalStateException("Already encoded!?");
    }
    long offset = offsetCrossSegmentBlocks[segNo] + (long) checkBlockNo * CHKBlock.DATA_LENGTH;
    raf.pwrite(offset, buf, 0, buf.length);
  }

  /**
   * Reads a cross-check block from the backing RAF.
   *
   * @param segNo zero-based cross-segment number whose block is being read; must be within range.
   * @param checkBlockNo zero-based cross-check block index within the cross-segment.
   * @return a new byte array of length {@link CHKBlock#DATA_LENGTH} containing the block data.
   * @throws IOException if the underlying RAF read fails at the computed offset.
   */
  public byte[] readCheckBlock(int segNo, int checkBlockNo) throws IOException {
    long offset = offsetCrossSegmentBlocks[segNo] + (long) checkBlockNo * CHKBlock.DATA_LENGTH;
    byte[] buf = new byte[CHKBlock.DATA_LENGTH];
    raf.pread(offset, buf, 0, buf.length);
    return buf;
  }

  /**
   * Lock the main RAF open to avoid the pooled fd being closed when we are doing a major I/O
   * operation involving many reads/writes.
   */
  RAFLock lockRAF() throws IOException {
    return raf.lockOpen();
  }

  /**
   * Lock the originalData RAF open to avoid the pooled fd being closed when we are doing a major
   * I/O operation involving many reads/writes.
   *
   * @throws IOException
   */
  RAFLock lockUnderlying() throws IOException {
    return originalData.lockOpen();
  }

  /**
   * Reads a data block for the given segment.
   *
   * <p>For the final padded block, the bytes are read from the RAF area reserved for the padded
   * last block; otherwise, the data is read from the original data buffer at the computed offset.
   *
   * @param segNo zero-based segment number to read from; must reference an existing segment.
   * @param blockNo zero-based data block index within the segment (excluding check blocks).
   * @return a new byte array of length {@link CHKBlock#DATA_LENGTH} with the block contents.
   * @throws IOException if reading from the RAF or the original data buffer fails.
   */
  public byte[] readSegmentDataBlock(int segNo, int blockNo) throws IOException {
    byte[] buf = new byte[CHKBlock.DATA_LENGTH];
    if (hasPaddedLastBlock
        && segNo == segments.length - 1
        && blockNo == segments[segNo].dataBlockCount - 1) {
      // Don't need to lock, locking is just an optimisation.
      raf.pread(offsetPaddedLastBlock, buf, 0, buf.length);
      return buf;
    }
    long offset = underlyingOffsetDataSegments[segNo] + (long) blockNo * CHKBlock.DATA_LENGTH;
    originalData.pread(offset, buf, 0, buf.length);
    return buf;
  }

  /**
   * Writes a per-segment check block into the backing RAF.
   *
   * @param segNo zero-based segment number whose check block is being written.
   * @param checkBlockNo zero-based index of the check block within the segment.
   * @param buf byte array containing exactly {@link CHKBlock#DATA_LENGTH} bytes of block data.
   * @throws IOException if the write to the RAF fails at the target offset.
   */
  public void writeSegmentCheckBlock(int segNo, int checkBlockNo, byte[] buf) throws IOException {
    long offset = offsetSegmentCheckBlocks[segNo] + (long) checkBlockNo * CHKBlock.DATA_LENGTH;
    raf.pwrite(offset, buf, 0, buf.length);
  }

  /**
   * Reads a per-segment check block from the backing RAF.
   *
   * @param segNo zero-based segment number from which to read the check block.
   * @param checkBlockNo zero-based index of the check block within the segment.
   * @return a new byte array of length {@link CHKBlock#DATA_LENGTH} with the check block data.
   * @throws IOException if the underlying RAF read fails at the computed offset.
   */
  public byte[] readSegmentCheckBlock(int segNo, int checkBlockNo) throws IOException {
    byte[] buf = new byte[CHKBlock.DATA_LENGTH];
    long offset = offsetSegmentCheckBlocks[segNo] + (long) checkBlockNo * CHKBlock.DATA_LENGTH;
    raf.pread(offset, buf, 0, buf.length);
    return buf;
  }

  /**
   * Encode the Metadata. The caller must ensure that all segments have encoded keys first.
   *
   * @throws MissingKeyException This indicates disk corruption or a bug (e.g. not all segments had
   *     encoded keys). Since we don't checksum the blocks, there isn't much point in trying to
   *     recover from losing a key; but at least we can detect that there was a problem.
   *     <p>(Package-visible for unit tests)
   */
  Metadata encodeMetadata() throws IOException, MissingKeyException {
    ClientCHK[] dataKeys = new ClientCHK[totalDataBlocks + crossCheckBlocks * segments.length];
    ClientCHK[] checkKeys = new ClientCHK[totalCheckBlocks];
    int dataPtr = 0;
    int checkPtr = 0;
    for (SplitFileInserterSegmentStorage segment : segments) {
      for (int i = 0; i < segment.dataBlockCount + segment.crossCheckBlockCount; i++) {
        dataKeys[dataPtr++] = segment.readKey(i);
      }
      for (int i = 0; i < segment.checkBlockCount; i++) {
        checkKeys[checkPtr++] =
            segment.readKey(i + segment.dataBlockCount + segment.crossCheckBlockCount);
      }
    }
    assert (dataPtr == dataKeys.length);
    assert (checkPtr == checkKeys.length);
    return new Metadata(
        splitfileType,
        dataKeys,
        checkKeys,
        segmentSize,
        checkSegmentSize,
        deductBlocksFromSegments,
        clientMetadata,
        dataLength,
        archiveType,
        compressionCodec,
        decompressedLength,
        isMetadata,
        hashes,
        hashThisLayerOnly,
        origDataSize,
        origCompressedDataSize,
        topRequiredBlocks,
        topTotalBlocks,
        topDontCompress,
        cmode,
        splitfileCryptoAlgorithm,
        splitfileCryptoKey,
        specifySplitfileKeyInMetadata,
        crossCheckBlocks);
  }

  void innerWriteSegmentKey(int segNo, int blockNo, byte[] buf) throws IOException {
    assert (buf.length == SplitFileInserterSegmentStorage.getKeyLength(this));
    assert (segNo >= 0 && segNo < segments.length);
    assert (blockNo >= 0 && blockNo < segments[segNo].totalBlockCount);
    long fileOffset = this.offsetSegmentKeys[segNo] + (long) keyLength * blockNo;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Writing key for block {} for segment {} of {} to {}", blockNo, segNo, this, fileOffset);
    raf.pwrite(fileOffset, buf, 0, buf.length);
  }

  byte[] innerReadSegmentKey(int segNo, int blockNo) throws IOException {
    byte[] buf = new byte[keyLength];
    long fileOffset = this.offsetSegmentKeys[segNo] + (long) keyLength * blockNo;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Reading key for block {} for segment {} of {} to {}", blockNo, segNo, this, fileOffset);
    raf.pread(fileOffset, buf, 0, buf.length);
    return buf;
  }

  /**
   * Returns the total number of cross-check blocks across all cross-segments.
   *
   * @return {@code segments.length * crossCheckBlocks}; zero when cross-segment redundancy is
   *     disabled.
   */
  @SuppressWarnings("unused")
  public int totalCrossCheckBlocks() {
    return segments.length * crossCheckBlocks;
  }

  /**
   * Notifies that a segment has completed successfully.
   *
   * <p>The notification is processed asynchronously; when all segments succeed, the storage
   * finalizes by encoding metadata and notifying the callback of success.
   *
   * @param completedSegment the segment that completed; used for logging and task routing.
   */
  public void segmentSucceeded(final SplitFileInserterSegmentStorage completedSegment) {
    if (LOG.isDebugEnabled()) LOG.debug("Succeeded segment {} for {}", completedSegment, callback);
    jobRunner.queueNormalOrDrop(context -> onSegmentSucceededTask(completedSegment));
  }

  private boolean onSegmentSucceededTask(SplitFileInserterSegmentStorage completedSegment) {
    if (LOG.isDebugEnabled()) LOG.debug("Succeeding segment {} for {}", completedSegment, callback);
    if (maybeFail()) return true;
    if (allSegmentsSucceeded()) {
      return completeAndNotifySuccess();
    } else {
      if (LOG.isDebugEnabled()) LOG.debug("Not all segments succeeded for {}", this);
      return true;
    }
  }

  private boolean completeAndNotifySuccess() {
    synchronized (this) {
      assert (failing == null);
      if (hasFinished()) return false;
      status = Status.GENERATING_METADATA;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Generating metadata...");
    try {
      Metadata metadata = encodeMetadata();
      synchronized (this) {
        status = Status.SUCCEEDED;
      }
      callback.onSucceeded(metadata);
    } catch (IOException e) {
      failWith(new InsertException(InsertExceptionMode.BUCKET_ERROR));
    } catch (MissingKeyException e) {
      // Fail here too. If we're getting disk corruption on keys, we're probably
      // getting it on the original data too.
      failWith(new InsertException(InsertExceptionMode.BUCKET_ERROR, "Missing keys", null));
    }
    return true;
  }

  private void failWith(InsertException e1) {
    synchronized (this) {
      failing = e1;
      status = Status.FAILED;
    }
    callback.onFailed(e1);
  }

  private boolean maybeFail() {
    // Might have failed.
    // Have to check segments before checking for failure because of race conditions.
    if (allSegmentsCompletedOrFailed()) {
      InsertException e;
      synchronized (this) {
        if (failing == null) return false;
        e = failing;
        if (hasFinished()) {
          if (LOG.isDebugEnabled()) LOG.debug("Maybe fail returning true because already finished");
          return true;
        }
        status = Status.FAILED;
      }
      if (LOG.isDebugEnabled())
        LOG.debug("Maybe fail returning true with error {}", String.valueOf(e));
      callback.onFailed(e);
      return true;
    } else {
      return false;
    }
  }

  private boolean allSegmentsCompletedOrFailed() {
    for (SplitFileInserterSegmentStorage segment : segments) {
      if (!segment.hasCompletedOrFailed()) return false;
    }
    for (SplitFileInserterCrossSegmentStorage segment : crossSegments) {
      if (!segment.hasCompletedOrFailed()) {
        return false;
      }
    }
    return true;
  }

  private boolean allSegmentsSucceeded() {
    for (SplitFileInserterSegmentStorage segment : segments) {
      if (!segment.hasSucceeded()) return false;
      if (LOG.isDebugEnabled()) LOG.debug("Succeeded {}", segment);
    }
    return true;
  }

  /**
   * Records a failure mode for later reporting and persists overall status.
   *
   * @param e insert exception whose mode should be counted toward aggregated failure statistics.
   */
  public void addFailure(InsertException e) {
    errors.inc(e.getMode());
    synchronized (this) {
      overallStatusDirty = true;
      lazyWriteMetadata();
    }
  }

  /**
   * Fails the storage with a disk or bucket I/O error.
   *
   * @param e the I/O exception that triggered the failure; wrapped into an {@link InsertException}.
   */
  public void failOnDiskError(IOException e) {
    fail(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null));
  }

  /** Marks the storage as failed due to fatal errors while encoding blocks. */
  public void failFatalErrorInBlock() {
    fail(new InsertException(InsertExceptionMode.FATAL_ERRORS_IN_BLOCKS, errors, null));
  }

  /** Marks the storage as failed due to exceeding the retry budget while encoding blocks. */
  public void failTooManyRetriesInBlock() {
    fail(new InsertException(InsertExceptionMode.TOO_MANY_RETRIES_IN_BLOCKS, errors, null));
  }

  void fail(final InsertException e) {
    synchronized (this) {
      if (this.status == Status.SUCCEEDED
          || this.status == Status.FAILED
          || this.status == Status.GENERATING_METADATA) {
        LOG.error("Already finished ({}) but failing with {} ({})", status, e, this, e);
        return;
      }
      if (failing != null) return; // Only fail once.
      failing = e;
    }
    if (e.mode == InsertExceptionMode.BUCKET_ERROR || e.mode == InsertExceptionMode.INTERNAL_ERROR)
      LOG.error("Failing: {} for {}", e, this, e);
    else LOG.info("Failing: {} for {}", e, this, e);
    jobRunner.queueNormalOrDrop(context -> onFailTask(e));
  }

  private boolean onFailTask(InsertException e) {
    boolean allDone = cancelAllSegments();
    if (crossSegments.length != 0) allDone &= cancelAllCrossSegments();
    if (allDone) {
      synchronized (this) {
        if (hasFinished()) return false; // Could have beaten us to it in callback.
        status = Status.FAILED;
      }
      callback.onFailed(e);
      return true;
    }
    // Wait for them to finish encoding.
    return false;
  }

  private boolean cancelAllSegments() {
    boolean allDone = true;
    for (SplitFileInserterSegmentStorage segment : segments) {
      if (!segment.cancel()) allDone = false;
    }
    return allDone;
  }

  private boolean cancelAllCrossSegments() {
    boolean allDone = true;
    for (SplitFileInserterCrossSegmentStorage segment : crossSegments) {
      if (!segment.cancel()) allDone = false;
    }
    return allDone;
  }

  /**
   * Reports whether the storage reached a terminal state.
   *
   * @return {@code true} when the status is {@code SUCCEEDED} or {@code FAILED}; otherwise {@code
   *     false}.
   */
  public synchronized boolean hasFinished() {
    return status == Status.SUCCEEDED || status == Status.FAILED;
  }

  synchronized Status getStatus() {
    return status;
  }

  static final long LAZY_WRITE_METADATA_DELAY = TimeUnit.MINUTES.toMillis(5);

  private final PersistentJob writeMetadataJob;

  private final Runnable wrapLazyWriteMetadata;

  /**
   * Schedules a deferred metadata write for persistent inserts.
   *
   * <p>When enabled, the write is queued on the ticker with a delay to coalesce frequent updates.
   * If the delay is zero, the write job is queued immediately on the persistent runner.
   */
  public synchronized void lazyWriteMetadata() {
    if (!persistent) return;
    if (LAZY_WRITE_METADATA_DELAY != 0) {
      // The Runnable must be the same object for de-duplication.
      ticker.queueTimedJob(
          wrapLazyWriteMetadata,
          "Write metadata for splitfile",
          LAZY_WRITE_METADATA_DELAY,
          false,
          true);
    } else { // Must still be off-thread, multiple segments, possible locking issues...
      jobRunner.queueNormalOrDrop(writeMetadataJob);
    }
  }

  /**
   * Indicates whether the storage is in the process of finishing.
   *
   * @return {@code true} when a failure is pending or the status is terminal or generating
   *     metadata; otherwise {@code false}.
   */
  protected synchronized boolean isFinishing() {
    return this.failing != null
        || status == Status.FAILED
        || status == Status.SUCCEEDED
        || status == Status.GENERATING_METADATA;
  }

  void onShutdown(ClientContext context) {
    writeMetadataJob.run(context);
  }

  private PersistentJob createWriteMetadataJob() {
    return context -> {
      try {
        if (isFinishing()) return false;
        RAFLock lock = raf.lockOpen();
        try {
          for (SplitFileInserterSegmentStorage segment : segments) {
            segment.storeStatus(false);
          }
        } finally {
          lock.unlock();
        }
        writeOverallStatus(false);
        return false;
      } catch (IOException e) {
        if (isFinishing()) return false;
        LOG.error("Failed writing metadata for {}: {}", SplitFileInserterStorage.this, e, e);
        return false;
      }
    };
  }

  @SuppressWarnings("SameParameterValue")
  void preadChecksummed(long fileOffset, byte[] buf, int offset, int length)
      throws IOException, ChecksumFailedException {
    byte[] checksumBuf = new byte[checker.checksumLength()];
    RAFLock lock = raf.lockOpen();
    try {
      raf.pread(fileOffset, buf, offset, length);
      raf.pread(fileOffset + length, checksumBuf, 0, checker.checksumLength());
    } finally {
      lock.unlock();
    }
    if (!checker.checkChecksum(buf, offset, length, checksumBuf)) {
      Arrays.fill(buf, offset, offset + length, (byte) 0);
      throw new ChecksumFailedException();
    }
  }

  @SuppressWarnings("unused")
  byte[] preadChecksummedWithLength(long fileOffset)
      throws IOException, ChecksumFailedException, StorageFormatException {
    byte[] checksumBuf = new byte[checker.checksumLength()];
    RAFLock lock = raf.lockOpen();
    byte[] lengthBuf = new byte[8];
    byte[] buf;
    int length;
    try {
      raf.pread(fileOffset, lengthBuf, 0, lengthBuf.length);
      long len;
      try (DataInputStream din = new DataInputStream(new ByteArrayInputStream(lengthBuf))) {
        len = din.readLong();
      }
      if (len + fileOffset > rafLength || len > Integer.MAX_VALUE || len < 0)
        throw new StorageFormatException("Bogus length " + len);
      length = (int) len;
      buf = new byte[length];
      raf.pread(fileOffset + lengthBuf.length, buf, 0, length);
      raf.pread(fileOffset + length + lengthBuf.length, checksumBuf, 0, checker.checksumLength());
    } finally {
      lock.unlock();
    }
    if (!checker.checkChecksum(buf, 0, length, checksumBuf)) {
      Arrays.fill(buf, 0, length, (byte) 0);
      throw new ChecksumFailedException();
    }
    return buf;
  }

  /**
   * Returns the file offset of the persisted status section for a segment.
   *
   * @param segNo zero-based segment number whose status offset is requested.
   * @return absolute byte offset within the RAF where the segment status begins.
   */
  public long getOffsetSegmentStatus(int segNo) {
    return offsetSegmentStatus[segNo];
  }

  LockableRandomAccessBuffer getRAF() {
    return raf;
  }

  /**
   * Resumes encoding after a process restart or pause using the supplied context.
   *
   * <p>Cross-segment encoding is resumed first when required; otherwise, per-segment encoding is
   * resumed directly.
   *
   * @param context active client context providing executors and services for resume.
   */
  public void onResume(ClientContext context) {
    if (LOG.isDebugEnabled()) LOG.debug("onResume with context {}", context);
    if (crossSegments.length != 0 && status != Status.ENCODED_CROSS_SEGMENTS) {
      this.startCrossSegmentEncode();
    } else {
      this.startSegmentEncode();
    }
  }

  /**
   * Choose a block to insert. Make SplitFileInserterSender per-segment to eliminate unnecessary
   * complexity.
   */
  BlockInsert chooseBlock() {
    // This should probably use SimpleBlockChooser and hence use lowest-retry-count from
    // each segment?
    // Less important for inserts than for requests though...
    synchronized (cooldownLock) {
      synchronized (this) {
        if (status == Status.FAILED
            || status == Status.SUCCEEDED
            || status == Status.GENERATING_METADATA
            || failing != null) {
          return null;
        }
      }
      // Generally segments are fairly well-balanced, so we can usually pick a random segment
      // then a random key from it.
      randomSegmentIterator.reset(random);
      while (randomSegmentIterator.hasNext()) {
        SplitFileInserterSegmentStorage segment = randomSegmentIterator.next();
        BlockInsert ret = segment.chooseBlock();
        if (ret != null) {
          noBlocksToSend = false;
          return ret;
        }
      }

      noBlocksToSend = true;
      return null;
    }
  }

  /**
   * Returns whether no blocks are currently available to send.
   *
   * @return {@code true} when a scheduling pass found no work; cleared by later progress events.
   */
  public boolean noBlocksToSend() {
    synchronized (cooldownLock) {
      return noBlocksToSend;
    }
  }

  /**
   * Returns the total number of keys (data + check + cross-check) tracked by all segments.
   *
   * @return sum of {@code totalBlockCount} across all segments; may be large for multi-segment
   *     inserts.
   */
  public long countAllKeys() {
    long total = 0;
    for (SplitFileInserterSegmentStorage segment : segments) total += segment.totalBlockCount;
    return total;
  }

  /**
   * Returns the total number of keys that are ready to send across all segments.
   *
   * @return count of keys currently considered sendable by each segment's chooser.
   */
  public long countSendableKeys() {
    long total = 0;
    for (SplitFileInserterSegmentStorage segment : segments) total += segment.countSendableKeys();
    return total;
  }

  /**
   * Returns the total number of blocks (data + check + cross-check) in the insert.
   *
   * @return combined block count across data, per-segment check blocks, and cross-check blocks.
   */
  public int getTotalBlockCount() {
    return totalDataBlocks + totalCheckBlocks + crossCheckBlocks * segments.length;
  }

  /**
   * Clears the internal cooldown indicator and notifies the callback.
   *
   * <p>After clearing, the scheduler may attempt new work selection immediately.
   */
  public void clearCooldown() {
    synchronized (cooldownLock) {
      noBlocksToSend = false;
    }
    this.callback.clearCooldown();
  }

  /**
   * Computes the scheduler wake-up hint for the insert.
   *
   * @param context active client context; used for logging and may influence policy externally.
   * @param now current wall-clock time in milliseconds since the epoch; used for tracing only.
   * @return {@code -1} when finished; {@code 0} when work is available now; otherwise {@code
   *     Long.MAX_VALUE} to indicate no immediate work.
   */
  public long getWakeupTime(ClientContext context, long now) {
    if (LOG.isTraceEnabled()) LOG.trace("getWakeupTime(ctx={}, now={})", context, now);
    // LOCKING: hasFinished() uses (this), separate from cooldownLock.
    // It is safe to use both here (on the request selection thread), one after the other.
    if (hasFinished()) return -1;
    if (noBlocksToSend()) return Long.MAX_VALUE;
    else return 0;
  }
}

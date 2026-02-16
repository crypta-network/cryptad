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
import network.crypta.client.MetadataTopLayerInfo;
import network.crypta.client.SplitfileBlockKeys;
import network.crypta.client.SplitfileCryptoParams;
import network.crypta.client.SplitfileParams;
import network.crypta.client.SplitfilePayload;
import network.crypta.client.SplitfileSegmentLayout;
import network.crypta.client.TopLayerBlockInfo;
import network.crypta.client.TopLayerHashInfo;
import network.crypta.client.async.SplitFileInserterSegmentStorage.BlockInsert;
import network.crypta.client.async.SplitFileInserterSegmentStorage.MissingKeyException;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.crypt.HashResult;
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
import network.crypta.support.io.NullBucket;
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
 * <p>When used persistently, the file layout is check-summed in bounded sections and includes: (1)
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
 *   <li>Responsibilities: encode per-segment/cross-segment settings; store and read check-summed
 *       sections; surface progress and failures to the callback; support resume and lazy metadata
 *       writing.
 *   <li>Notable behaviors: non-redundant mode omits check and cross-check data; offsets and lengths
 *       are validated when resuming; operations use a {@link ChecksumChecker} to protect section
 *       boundaries against corruption.
 * </ul>
 */
public final class SplitFileInserterStorage {
  private static final Logger LOG = LoggerFactory.getLogger(SplitFileInserterStorage.class);

  /** The original file to upload */
  final LockableRandomAccessBuffer originalData;

  /** The RAF containing check blocks, status, etc. */
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
   * Length in bytes of the data being uploaded, i.e., the original file, ignoring padding, check
   * blocks, etc.
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

  private volatile Status status;
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
   * cross-segment structures, and, when persistence is enabled, materializes a check-summed RAF
   * that can be used to resume the insert after a process restart. No network activity occurs here;
   * the caller controls lifecycle and scheduling via the associated inserter callback. The instance
   * holds references to the provided buffers and helpers, so callers must keep them valid for the
   * lifetime of the insert.
   *
   * <p>Initialization validates sizes, computes redundancy, allocates per-segment state, and
   * derives crypto settings consistent with the supplied compatibility mode. The RAF layout is
   * deterministic, allowing the inserter to resume without re-deriving segment boundaries. This
   * constructor does not start encoding; callers must invoke {@link #start()} to begin work.
   *
   * @param params initialization parameters capturing inputs, encoding metadata, and runtime
   *     services; must be non-null and internally consistent.
   * @throws IOException if persistent RAF initialization fails due to I/O errors.
   * @throws InsertException if inputs are inconsistent, oversized, or temporary storage fails.
   */
  public SplitFileInserterStorage(SplitFileInserterStorageInitParams params)
      throws IOException, InsertException {
    SplitFileInserterStorageRuntimeParams runtime = params.runtime;
    LockableRandomAccessBuffer inputData = params.originalData;
    this.originalData = inputData;
    this.callback = runtime.callback;
    this.persistent = params.persistent;
    LockableRandomAccessBufferFactory rafFactory = params.rafFactory;
    dataLength = inputData.size();
    if (dataLength > ((long) Integer.MAX_VALUE) * CHKBlock.DATA_LENGTH)
      throw new InsertException(InsertExceptionMode.TOO_BIG);
    totalDataBlocks = (int) ((dataLength + CHKBlock.DATA_LENGTH - 1) / CHKBlock.DATA_LENGTH);
    this.decompressedLength = params.decompressedLength;
    this.compressionCodec = params.compressionCodec;
    this.clientMetadata = params.meta;
    this.checker = params.checker;
    this.memoryLimitedJobRunner = runtime.memoryLimitedJobRunner;
    this.jobRunner = runtime.jobRunner;
    this.isMetadata = params.isMetadata;
    this.archiveType = params.archiveType;
    this.hashThisLayerOnly = copyByteArray(params.hashThisLayerOnly);
    this.topDontCompress = params.topDontCompress;
    this.origDataSize = params.origDataSize;
    this.origCompressedDataSize = params.origCompressedDataSize;
    this.maxRetries = params.ctx.getMaxInsertRetries();
    this.errors = new FailureCodeTracker(true);
    this.ticker = runtime.ticker;
    this.random = runtime.random;

    // Work out how many blocks in each segment, crypto keys, etc.
    // Complicated by back compatibility, i.e., the need to be able to
    // reinsert old splitfiles.
    // Consider getting rid of support for very old splitfiles.

    InsertContext ctx = params.ctx;
    byte[] providedSplitfileCryptoKey = copyByteArray(params.splitfileCryptoKey);
    cmode = ctx.getCompatibilityMode();
    if (cmode.code < CompatibilityMode.COMPAT_1255.code) {
      this.hashes = null;
      providedSplitfileCryptoKey = null;
    } else {
      this.hashes = copyHashArray(params.hashes);
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

    this.splitfileCryptoAlgorithm = params.splitfileCryptoAlgorithm;
    CryptoInit crypto =
        chooseSplitfileKey(
            providedSplitfileCryptoKey, cmode, params.hashThisLayerOnly, this.hashes);
    this.splitfileCryptoKey = copyByteArray(crypto.key);
    specifySplitfileKeyInMetadata = crypto.specifyInMetadata;

    int totalCheckBlocksLocal = 0;
    int checkTotalDataBlocks = 0;
    underlyingOffsetDataSegments = new long[segs];
    keyLength = SplitFileInserterSegmentStorage.getKeyLength(this);
    this.consecutiveRNFsCountAsSuccess = ctx.getConsecutiveRNFsCountAsSuccess();
    segments =
        makeSegments(
            segmentSize,
            segs,
            totalDataBlocks,
            deductBlocksFromSegments,
            runtime.keysFetching,
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
    // computedCrossCheckBlocks suggest redundancy for large segment counts.
    crossSegments =
        initCrossSegmentsIfAny(segs, this.crossCheckBlocks, segmentSize, deductBlocksFromSegments);

    // Now set up the RAF.

    // Set up offset arrays early so we can compute the length of encodeOffsets().
    OffsetArrays oa = createOffsetArrays(persistent);
    offsetCrossSegmentBlocks = copyLongArray(oa.offsetCrossSegmentBlocks);
    offsetCrossSegmentStatus = copyLongArray(oa.offsetCrossSegmentStatus);
    offsetSegmentCheckBlocks = copyLongArray(oa.offsetSegmentCheckBlocks);
    offsetSegmentStatus = copyLongArray(oa.offsetSegmentStatus);
    offsetSegmentKeys = copyLongArray(oa.offsetSegmentKeys);

    // First, we have all the fixed stuff ...

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
      PersistenceInit p = preparePersistenceInit(params.tempBucketFactory);
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
    // Encrypted RAFs are not initialized with 0's, so we need to clear explicitly (we do store keys
    // even for transient inserts).
    for (SplitFileInserterSegmentStorage segment : segments) {
      segment.clearKeys();
    }
    // Keys are empty and invalid.
    status = Status.NOT_STARTED;

    // Include the cross-check blocks in the required blocks. The actual number needed may be
    // slightly less, but this is consistent with fetching, and also with pre-1468 metadata.
    int totalCrossCheckBlocks = crossCheckBlocks * segments.length;
    this.topRequiredBlocks = params.topRequiredBlocks + totalDataBlocks + totalCrossCheckBlocks;
    this.topTotalBlocks =
        params.topTotalBlocks + totalDataBlocks + totalCrossCheckBlocks + totalCheckBlocks;

    this.writeMetadataJob = createWriteMetadataJob();
    this.wrapLazyWriteMetadata = () -> jobRunner.queueNormalOrDrop(writeMetadataJob);
  }

  /**
   * Reconstructs storage state from a previously persisted RAF.
   *
   * <p>This constructor validates the file format, verifies each check-summed section, restores the
   * original data reference, and rebuilds per-segment and optional cross-segment state. It throws
   * descriptive exceptions when the header is invalid, checksums fail, offsets are out of range, or
   * the original data size does not match the stored header.
   *
   * <p>Resume restores only the metadata and bookkeeping necessary to continue an interrupted
   * insert; it does not restart encoding or schedule network work. Callers are responsible for
   * resuming dependent buffers before construction and for invoking {@link
   * #onResume(ClientContext)} afterward to reconnect runtime scheduling and callbacks. The
   * persisted RAF is treated as the source of truth for segment counts, offsets, and status
   * lengths.
   *
   * @param params resume parameters, including buffers, runtime helpers, and decryption material,
   *     must be non-null and correspond to the persisted format.
   * @throws IOException if reading the RAF fails due to I/O errors while restoring sections.
   * @throws StorageFormatException if the file format is invalid, contains out-of-range values, or
   *     violates invariants expected by this version.
   * @throws ChecksumFailedException if any checksummed section fails verification during restore.
   * @throws ResumeFailedException if the supplied {@code originalData} size differs from the stored
   *     value or is otherwise incompatible with the header.
   */
  public SplitFileInserterStorage(SplitFileInserterStorageResumeParams params)
      throws IOException, StorageFormatException, ChecksumFailedException, ResumeFailedException {
    SplitFileInserterStorageRuntimeParams runtime = params.runtime;
    this.persistent = true;
    this.callback = runtime.callback;
    this.ticker = runtime.ticker;
    this.memoryLimitedJobRunner = runtime.memoryLimitedJobRunner;
    this.jobRunner = runtime.jobRunner;
    this.random = runtime.random;
    this.raf = params.raf;
    rafLength = params.raf.size();
    long maxLength = Long.MAX_VALUE;
    try (InputStream ois = new RAFInputStream(this.raf, 0, rafLength);
        DataInputStream header = new DataInputStream(ois)) {
      validateMagic(header.readLong());
      int checksumType = header.readInt();
      this.checker = createChecksumChecker(checksumType);

      int segmentCount;
      try (InputStream is =
              checker.checksumReaderWithLength(ois, new ArrayBucketFactory(), maxLength);
          DataInputStream dis = new DataInputStream(is)) {
        validateVersion(dis.readInt());
        LockableRandomAccessBuffer rafOrig =
            BucketTools.restoreRAFFrom(
                dis, params.persistentFG, params.persistentFileTracker, params.masterKey);
        LockableRandomAccessBuffer resumeOriginalData = params.originalData;
        this.originalData = chooseOriginalData(resumeOriginalData, rafOrig);
        this.totalDataBlocks = readPositiveInt(dis, "total data blocks");
        this.totalCheckBlocks = readPositiveInt(dis, "total check blocks");
        this.splitfileType = readSplitfileAlgorithm(dis);
        this.codec = getCodecFor(splitfileType);
        this.dataLength = readPositiveLong(dis, "data length");
        validateDataLengthMatches(dataLength, resumeOriginalData);
        validateBlockCountCompatibility(dataLength, totalDataBlocks);
        decompressedLength = readPositiveLong(dis, "decompressed length");
        isMetadata = dis.readBoolean();
        archiveType = readArchiveType(dis.readShort());
        clientMetadata = readClientMetadata(dis);
        compressionCodec = readCompressionCodec(dis);
        segmentCount = readPositiveInt(dis, "segment count");
        this.segmentSize = readPositiveInt(dis, "segment size");
        // Allow zero for NON_REDUNDANT splitfiles (codec == null), where no check blocks exist.
        this.checkSegmentSize = readCheckSegmentSize(dis);
        int ccb = dis.readInt();
        if (ccb < 0) throw new StorageFormatException("Bad cross-check block count");
        this.crossCheckBlocks = ccb;
        validateSegmentTotals(segmentSize, checkSegmentSize, crossCheckBlocks);
        this.splitfileCryptoAlgorithm = dis.readByte();
        validateCryptoAlgorithm(splitfileCryptoAlgorithm);
        splitfileCryptoKey = copyByteArray(readOptionalCryptoKey(dis));
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
        hashThisLayerOnly = copyByteArray(readOptionalHashThisLayerOnly(dis));
        topDontCompress = dis.readBoolean();
        topRequiredBlocks = dis.readInt();
        topTotalBlocks = dis.readInt();
        origDataSize = dis.readLong();
        origCompressedDataSize = dis.readLong();
        hashes = copyHashArray(HashResult.readHashes(dis));
      }
      this.hasPaddedLastBlock = (dataLength % CHKBlock.DATA_LENGTH != 0);
      this.segments = new SplitFileInserterSegmentStorage[segmentCount];
      randomSegmentIterator = new RandomArrayIterator<>(segments);
      this.crossSegments = initCrossSegmentsArrayIfAny(segmentCount);
      // Read offsets.
      OffsetsData od;
      try (InputStream is =
              checker.checksumReaderWithLength(ois, new ArrayBucketFactory(), maxLength);
          DataInputStream dis = new DataInputStream(is)) {
        od = readOffsets(dis, rafLength, segmentCount);
      }
      offsetPaddedLastBlock = od.offsetPaddedLastBlock;
      offsetOverallStatus = od.offsetOverallStatus;
      overallStatusLength = od.overallStatusLength;
      offsetCrossSegmentBlocks = copyLongArray(od.arrays.offsetCrossSegmentBlocks);
      offsetSegmentCheckBlocks = copyLongArray(od.arrays.offsetSegmentCheckBlocks);
      offsetSegmentStatus = copyLongArray(od.arrays.offsetSegmentStatus);
      offsetCrossSegmentStatus = copyLongArray(od.arrays.offsetCrossSegmentStatus);
      offsetSegmentKeys = copyLongArray(od.arrays.offsetSegmentKeys);
      // Set up segments...
      underlyingOffsetDataSegments = new long[segmentCount];
      try (InputStream is =
          checker.checksumReaderWithLength(ois, new ArrayBucketFactory(), maxLength)) {
        long blocks = initSegmentsAndComputeBlocks(is, segmentCount, runtime.keysFetching);
        if (blocks != totalDataBlocks)
          throw new StorageFormatException(
              "Total data blocks should be " + totalDataBlocks + " but is " + blocks);
      }
      readCrossSegmentsFromDisk(ois, maxLength);
    }
    errors = readStatusesFromDisk(maxLength);
    computeStatus();

    this.writeMetadataJob = createWriteMetadataJob();
    this.wrapLazyWriteMetadata = () -> jobRunner.queueNormalOrDrop(writeMetadataJob);
  }

  private static byte[] copyByteArray(byte[] input) {
    return input == null ? null : Arrays.copyOf(input, input.length);
  }

  private static long[] copyLongArray(long[] input) {
    return input == null ? null : Arrays.copyOf(input, input.length);
  }

  private static HashResult[] copyHashArray(HashResult[] input) {
    return input == null ? null : Arrays.copyOf(input, input.length);
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
    // The last 3 statuses are only used during completion.
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
                ctx.getSplitfileSegmentDataBlocks());
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
        || cmode.code >= CompatibilityMode.COMPAT_1255.code) {
      int lastSegmentSize = totalDataBlocks - (segmentSize * (segs - 1));
      return segmentSize - lastSegmentSize;
    }
    return 0;
  }

  private int computeCrossCheckBlocks(int segs, CompatibilityMode cmode) {
    // Cross-segment splitfile redundancy becomes useful at 20 segments.
    if (segs >= 20
        && (cmode == CompatibilityMode.COMPAT_CURRENT
            || cmode.code >= CompatibilityMode.COMPAT_1255.code)) {
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
      dos.writeInt(cmode.code);
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
    short compatCode = (short) compatMode;
    if (!CompatibilityMode.hasCode(compatCode))
      throw new StorageFormatException("Invalid compatibility mode " + compatMode);
    return CompatibilityMode.byCode(compatCode);
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
    // When there are no cross-check blocks, we do not write any cross-segment
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
    } catch (IllegalArgumentException _) {
      throw new StorageFormatException("Bad checksum type");
    }
  }

  private SplitfileAlgorithm readSplitfileAlgorithm(DataInputStream dis)
      throws IOException, StorageFormatException {
    try {
      return SplitfileAlgorithm.getByCode(dis.readShort());
    } catch (IllegalArgumentException _) {
      throw new StorageFormatException("Bad splitfile type");
    }
  }

  private FECCodec getCodecFor(SplitfileAlgorithm algorithm) throws StorageFormatException {
    try {
      return FECCodec.getInstance(algorithm);
    } catch (IllegalArgumentException _) {
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

  @SuppressWarnings("ClassCanBeRecord")
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
        || cmode.code >= CompatibilityMode.COMPAT_1255.code) {
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

  @SuppressWarnings("ClassCanBeRecord")
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

  @SuppressWarnings("ClassCanBeRecord")
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
    } catch (IOException _) {
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
      if (LOG.isDebugEnabled()) LOG.debug("Clearing segment status for {}", segment);
      segment.storeStatus(true);
    }
    if (crossSegments != null) {
      for (SplitFileInserterCrossSegmentStorage segment : crossSegments) {
        if (LOG.isDebugEnabled()) LOG.debug("Clearing cross-segment status for {}", segment);
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
   *
   * <p>The call updates the status machine from {@code NOT_STARTED} to {@code STARTED}, checks for
   * early-exit terminal states, and triggers the appropriate encoding phase. It does not perform
   * any network I/O; it merely schedules encoder work and records progress. If encoding is already
   * complete, or if the storage has failed, the method does nothing and returns immediately.
   * Callers can safely invoke this multiple times from the inserter lifecycle.
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
      // Cross-segment encode must complete before the main encoding.
      startCrossSegmentEncode();
    }
  }

  /**
   * Returns the number of segments that have completed encoding.
   *
   * <p>The result is a snapshot taken at the time of the call and may change as background encoding
   * progresses. This method does not acquire long-running locks and does not block on ongoing
   * encoding work, so it may undercount segments that are finishing concurrently.
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
   * <p>The count reflects the current completion flags on cross-segment encoders. It is intended
   * for progress reporting and logging and does not imply that all data blocks are already
   * available for insertion. The value may change as encoding jobs complete asynchronously.
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
   * <p>This method is typically called by a {@link SplitFileInserterCrossSegmentStorage} instance
   * once it has written its check blocks. The storage updates progress, clears cooldown state for
   * scheduling, and triggers the next phase only when every cross-segment reports completion. The
   * method does not block on I/O; it queues work on the job runner and returns promptly.
   *
   * @param completed the cross-segment that completed encoding; used for logging and progress
   *     checks only.
   */
  public void onFinishedEncoding(SplitFileInserterCrossSegmentStorage completed) {
    if (LOG.isDebugEnabled()) LOG.debug("Cross-segment finished encoding: {}", completed);
    jobRunner.queueNormalOrDrop(
        _ -> {
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
   * <p>This callback is invoked by a segment encoder after it has generated and stored check
   * blocks. The storage clears cooldown state, persists per-segment status, and schedules metadata
   * generation only when all segments report completion. The call itself does not block on disk I/O
   * beyond the status writing initiated by the segment.
   *
   * @param completed the segment that completed encoding; used to persist status and track
   *     aggregate progress.
   */
  public void onFinishedEncoding(final SplitFileInserterSegmentStorage completed) {
    jobRunner.queueNormalOrDrop(
        _ -> {
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
        LOG.error("Cross-segment encode completed in wrong state {} for {}", status, this);
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
        LOG.error("Segment encode completed in wrong state {} for {}", status, this);
        return;
      }
      status = Status.ENCODED;
    }
    callback.onFinishedEncode();
  }

  /**
   * Notifies that a segment got keys for all of its blocks.
   *
   * <p>When every segment reports it has keys, delegates to {@code onHasKeys()} to inform the
   * callback that metadata can be emitted early (depending on configuration).
   *
   * <p>The caller is expected to invoke this after the segment has generated or discovered all keys
   * for its data and check blocks. The method performs a lightweight scan across segments to verify
   * that all keys are now available before notifying the callback. It does not persist in any state
   * and returns immediately if any segment is still missing keys.
   *
   * @param splitFileInserterSegmentStorage the reporting segment instance; used for logging and
   *     diagnostics only.
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
   * @return an OutputStream that computes and appends a checksum, verifies the total written length
   *     equals {@code length}, and on close() writes the bytes to {@code raf} at {@code
   *     fileOffset}.
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
   * <p>The key is present when it was explicitly supplied or derived and must be persisted in the
   * metadata. For compatibility modes that derive the key implicitly, this method returns {@code
   * false} even though encryption still occurs.
   *
   * @return {@code true} when a 32-byte splitfile key is stored for this insert; otherwise {@code
   *     false} when the key is implicit or not required.
   */
  public boolean hasSplitfileKey() {
    return splitfileCryptoKey != null;
  }

  /**
   * Write a cross-check block to the disk.
   *
   * @throws IOException if writing the block to the backing, RAF fails.
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
   * <p>This method performs a direct read at the computed offset and returns a fresh buffer. It
   * does not validate the checksum of the block; higher-level integrity checks are handled by the
   * inserter or by the encoded metadata.
   *
   * @param segNo zero-based cross-segment number whose block is being read; must be within range
   *     for the current cross-segment layout.
   * @param checkBlockNo zero-based cross-check block index within the cross-segment; must address a
   *     valid block.
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
   * @throws IOException if acquiring the lock on the underlying RAF fails.
   */
  RAFLock lockUnderlying() throws IOException {
    return originalData.lockOpen();
  }

  /**
   * Reads a data block for the given segment.
   *
   * <p>For the final padded block, the bytes are read from the RAF area reserved for the padded
   * last block; otherwise, the data is read from the original data buffer at the computed offset.
   * The returned buffer is always exactly {@link CHKBlock#DATA_LENGTH} bytes, even when the
   * original content length was not block-aligned.
   *
   * @param segNo zero-based segment number to read from; must reference an existing segment.
   * @param blockNo zero-based data block index within the segment; excludes check blocks.
   * @return a new byte array containing the block contents padded to full block size.
   * @throws IOException if reading from the RAF or the original data buffer fails.
   */
  public byte[] readSegmentDataBlock(int segNo, int blockNo) throws IOException {
    byte[] buf = new byte[CHKBlock.DATA_LENGTH];
    if (hasPaddedLastBlock
        && segNo == segments.length - 1
        && blockNo == segments[segNo].dataBlockCount - 1) {
      // Don't need to lock, locking is just an optimization.
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
   * <p>This method writes the provided block bytes to the persistent RAF at the offset assigned for
   * the target segment. The buffer length must match {@link CHKBlock#DATA_LENGTH}; no resizing or
   * padding occurs here.
   *
   * @param segNo zero-based segment number whose check block is being written.
   * @param checkBlockNo zero-based index of the check block within the segment; must be valid.
   * @param buf byte array containing exactly {@link CHKBlock#DATA_LENGTH} bytes of block data.
   * @throws IOException if the writing to the RAF fails at the target offset.
   */
  public void writeSegmentCheckBlock(int segNo, int checkBlockNo, byte[] buf) throws IOException {
    long offset = offsetSegmentCheckBlocks[segNo] + (long) checkBlockNo * CHKBlock.DATA_LENGTH;
    raf.pwrite(offset, buf, 0, buf.length);
  }

  /**
   * Reads a per-segment check block from the backing RAF.
   *
   * <p>The returned buffer is always a fresh allocation and is not cached. Callers should avoid
   * repeated reads when possible and use in-memory caches if they need the same block repeatedly.
   *
   * @param segNo zero-based segment number from which to read the check block.
   * @param checkBlockNo zero-based index of the check block within the segment; must be in range.
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
   * @throws MissingKeyException This indicates disk corruption or a bug (e.g., not all segments had
   *     encoded keys). Since we don't checksum the blocks, there isn't much point in trying to
   *     recover from losing a key, but at least we can detect that there was a problem.
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
    SplitfileParams params =
        new SplitfileParams(
            splitfileType,
            new SplitfileBlockKeys(dataKeys, checkKeys),
            new SplitfileSegmentLayout(
                segmentSize, checkSegmentSize, deductBlocksFromSegments, crossCheckBlocks),
            new SplitfileCryptoParams(
                splitfileCryptoAlgorithm, splitfileCryptoKey, specifySplitfileKeyInMetadata));
    SplitfilePayload payload =
        new SplitfilePayload(
            clientMetadata,
            dataLength,
            archiveType,
            compressionCodec,
            decompressedLength,
            isMetadata);
    TopLayerBlockInfo blockInfo =
        new TopLayerBlockInfo(
            origDataSize,
            origCompressedDataSize,
            topRequiredBlocks,
            topTotalBlocks,
            topDontCompress,
            cmode);
    TopLayerHashInfo hashInfo = new TopLayerHashInfo(hashes, hashThisLayerOnly);
    MetadataTopLayerInfo topLayer = new MetadataTopLayerInfo(blockInfo, hashInfo);
    return new Metadata(params, payload, topLayer);
  }

  void innerWriteSegmentKey(int segNo, int blockNo, byte[] buf) throws IOException {
    assert (buf.length == SplitFileInserterSegmentStorage.getKeyLength(this));
    assert (segNo >= 0 && segNo < segments.length);
    assert (blockNo >= 0 && blockNo < segments[segNo].totalBlockCount);
    long fileOffset = this.offsetSegmentKeys[segNo] + (long) keyLength * blockNo;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Writing segment key: block {} segment {} storage {} offset {}",
          blockNo,
          segNo,
          this,
          fileOffset);
    raf.pwrite(fileOffset, buf, 0, buf.length);
  }

  byte[] innerReadSegmentKey(int segNo, int blockNo) throws IOException {
    byte[] buf = new byte[keyLength];
    long fileOffset = this.offsetSegmentKeys[segNo] + (long) keyLength * blockNo;
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Reading segment key: block {} segment {} storage {} offset {}",
          blockNo,
          segNo,
          this,
          fileOffset);
    raf.pread(fileOffset, buf, 0, buf.length);
    return buf;
  }

  /**
   * Returns the total number of cross-check blocks across all cross-segments.
   *
   * <p>This value is derived from the configured cross-check block count per segment and the
   * current segment count. It is stable for the lifetime of the storage instance and is useful for
   * sizing buffers and reporting total block counts.
   *
   * @return the total count of cross-check blocks for this insert, or zero when redundancy is
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
   * <p>This method is safe to call from worker threads. It enqueues the completion work on the
   * persistent job runner to avoid blocking the caller with metadata generation or I/O. If a
   * failure is already pending, the completion path may be skipped in favor of the failure path.
   *
   * @param completedSegment the segment that completed; used for logging and task routing only.
   */
  public void segmentSucceeded(final SplitFileInserterSegmentStorage completedSegment) {
    if (LOG.isDebugEnabled())
      LOG.debug("Segment succeeded: {} (callback {})", completedSegment, callback);
    jobRunner.queueNormalOrDrop(_ -> onSegmentSucceededTask(completedSegment));
  }

  private boolean onSegmentSucceededTask(SplitFileInserterSegmentStorage completedSegment) {
    if (LOG.isDebugEnabled())
      LOG.debug("Processing segment success: {} (callback {})", completedSegment, callback);
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
    } catch (IOException _) {
      failWith(new InsertException(InsertExceptionMode.BUCKET_ERROR));
    } catch (MissingKeyException _) {
      // Fail here either. If we're getting disk corruption on keys, we're probably
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
   * <p>This method increments the failure counters that are persisted in the overall status
   * section. It does not immediately fail the insert; instead, it updates the aggregated error
   * state and schedules a lazy metadata writing so a future resuming can observe the updated
   * counts.
   *
   * @param e insert an exception whose mode should be counted toward aggregated failure statistics;
   *     must be non-null.
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
   * <p>The failure is converted to an {@link InsertException} with {@code BUCKET_ERROR} mode and
   * then processed through the standard failure path, which may cancel segments and notify the
   * callback once all segments finish.
   *
   * @param e the I/O exception that triggered the failure; wrapped into an {@link InsertException}
   *     for reporting.
   */
  public void failOnDiskError(IOException e) {
    fail(new InsertException(InsertExceptionMode.BUCKET_ERROR, e, null));
  }

  /**
   * Marks the storage as failed due to fatal errors while encoding blocks.
   *
   * <p>This is a terminal failure mode and indicates that blocks were corrupted or otherwise
   * unrecoverable. The failure is recorded and propagated through the same cancellation and
   * notification path as other fatal errors.
   */
  public void failFatalErrorInBlock() {
    fail(new InsertException(InsertExceptionMode.FATAL_ERRORS_IN_BLOCKS, errors, null));
  }

  /**
   * Marks the storage as failed due to exceeding the retry budget while encoding blocks.
   *
   * <p>This failure indicates repeated inability to insert blocks within the configured retry
   * limits. It records the failure and schedules cancellation and callback notification as the
   * remaining segments complete.
   */
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
      LOG.error("Failing insert (io/internal): {} for {}", e, this, e);
    else LOG.info("Failing insert (retry/fatal): {} for {}", e, this, e);
    jobRunner.queueNormalOrDrop(_ -> onFailTask(e));
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
   * <p>The terminal states are {@link Status#SUCCEEDED} and {@link Status#FAILED}. The method is
   * synchronized to provide a consistent snapshot of the status and does not block on ongoing
   * encoding or I/O work.
   *
   * @return {@code true} when the status is {@code SUCCEEDED} or {@code FAILED}; otherwise {@code
   *     false} while work is ongoing.
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
   * Schedules a deferred metadata writing for persistent inserts.
   *
   * <p>When enabled, the writing is queued on the ticker with a delay to coalesce frequent updates.
   * If the delay is zero, the writing job is queued immediately on the persistent runner.
   *
   * <p>This method is a no-op for transient inserts because no persistent RAF exists. It does not
   * block on I/O; it only schedules a job that will write metadata when the job runner executes.
   */
  public synchronized void lazyWriteMetadata() {
    if (!persistent) return;
    if (LAZY_WRITE_METADATA_DELAY != 0) {
      // The Runnable must be the same object for deduplication.
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
   * <p>The finishing window includes the final metadata generation phase and any pending failure
   * that has been recorded but not yet notified. Callers can use this to avoid scheduling new work
   * once the insert is effectively shutting down.
   *
   * @return {@code true} when a failure is pending or the status is terminal or generating
   *     metadata; otherwise {@code false}.
   */
  synchronized boolean isFinishing() {
    return this.failing != null
        || status == Status.FAILED
        || status == Status.SUCCEEDED
        || status == Status.GENERATING_METADATA;
  }

  void onShutdown(ClientContext context) {
    writeMetadataJob.run(context);
  }

  private PersistentJob createWriteMetadataJob() {
    return _ -> {
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
   * <p>The offset points to the check-summed status record for the given segment within the RAF.
   * Callers can use this to correlate RAF layout with segment indices or to perform low-level
   * diagnostics and validation of persisted state.
   *
   * @param segNo zero-based segment number whose status offset is requested; must be valid.
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
   * <p>This method does not restore the persisted state; it assumes the instance was constructed
   * from a valid RAF and only reconnects runtime scheduling with the provided context. It does not
   * block; it merely triggers the appropriate encoding phase and returns.
   *
   * @param context active client context providing executors and services for resume; must be
   *     non-null and configured for persistent operation.
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
    // Less important for inserts than for requests, though...
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
   * <p>The flag is updated during block selection and cleared when new encoding progress is
   * observed. It is intended as a lightweight scheduling hint rather than a precise measure of
   * insert completion.
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
   * <p>This count includes data blocks, per-segment check blocks, and any cross-segment check
   * blocks assigned to segments. It is stable for the lifetime of the storage and is useful for
   * progress percentages and UI reporting.
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
   * <p>The result depends on per-segment chooser state, retry limits, and cooldown policies. It
   * reflects a snapshot and may change as segments update their internal state or as blocks are
   * inserted.
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
   * <p>The value combines data blocks, per-segment check blocks, and cross-segment check blocks. It
   * is deterministic for a given insert configuration and is used for UI progress reporting and
   * quota accounting.
   *
   * @return combined block count across data, per-segment check blocks, and cross-check blocks.
   */
  public int getTotalBlockCount() {
    return totalDataBlocks + totalCheckBlocks + crossCheckBlocks * segments.length;
  }

  /**
   * Clears the internal cooldown indicator and notifies the callback.
   *
   * <p>After clearing, the scheduler may attempt a new work selection immediately. This method is
   * thread-safe and performs only a lightweight state update.
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
   * <p>The return value follows the scheduler contract: {@code -1} indicates completion, {@code 0}
   * means work is available immediately, and {@code Long.MAX_VALUE} signals no work until an
   * external event occurs. The decision is based on current status and the cooldown flag.
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

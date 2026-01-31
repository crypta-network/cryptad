package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FECCodec;
import network.crypta.client.FailureCodeTracker;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.Metadata;
import network.crypta.client.Metadata.SplitfileAlgorithm;
import network.crypta.client.MetadataParseException;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.ClientKey;
import network.crypta.keys.Key;
import network.crypta.node.SendableRequestItem;
import network.crypta.node.SendableRequestItemKey;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.RandomArrayIterator;
import network.crypta.support.Ticker;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBuffer.RAFLock;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.io.StorageFormatException;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Maintains a persistent and in-memory state for a splitfile fetch.
 *
 * <p>This storage binds a {@link SplitFileFetcher} to a single {@link LockableRandomAccessBuffer},
 * keeping hot metadata in memory while persisting block data, key lists, and progress so the fetch
 * can resume after restarts. Segments may be stored in temporary FEC order; decoding reconstructs
 * missing blocks and then rewrites data blocks into logical sequence. Callers create an instance
 * for a new fetch or resume one from disk, then drive scheduling through the owning fetcher until
 * completion.
 *
 * <p>The layout aims to minimize seeks and maximize robustness while tolerating recovery work after
 * checksum failures. Callbacks into the fetcher run off-thread via job runners, and locking is
 * shallow and taken last relatively to segment locks. The storage itself is transient and recreated
 * on startup; persisted sections carry enough states to rehydrate progress.
 *
 * <p>On-disk sections include:
 *
 * <ul>
 *   <li>Block storage for data and check blocks, organized per segment.
 *   <li>Segment key lists with per-segment checksums.
 *   <li>Segment status records with retry and block flags.
 *   <li>Main and per-segment Bloom filters for key lookup.
 *   <li>Original metadata/details and basic settings with a check-summed footer.
 * </ul>
 *
 * @see SplitFileFetcher
 * @see SplitFileFetcherSegmentStorage
 * @see SplitFileFetcherStoragePersistence
 * @author toad
 */
public class SplitFileFetcherStorage {
  static final Logger LOG = LoggerFactory.getLogger(SplitFileFetcherStorage.class);

  final SplitFileFetcherStorageCallback fetcher;

  // Metadata for the fetch
  /** The underlying presumably-on-disk storage. */
  private final LockableRandomAccessBuffer raf;

  private final long rafLength;

  /**
   * If true, we will complete the download by truncating the file. The file was passed in at
   * construction, and we are not responsible for freeing it. Once all segments have decoded and
   * encoded, we call onSuccess(), and we don't free the data. Also, if this is true, cross-check
   * blocks will be kept on disk *AFTER* all the main data and check blocks for the whole file.
   */
  final boolean completeViaTruncation;

  /** The segments */
  final SplitFileFetcherSegmentStorage[] segments;

  /** The cross-segments. Null if no cross-segments. */
  final SplitFileFetcherCrossSegmentStorage[] crossSegments;

  /** Random iterator for segment selection. LOCKING: must synchronize on the iterator. */
  private final RandomArrayIterator<SplitFileFetcherSegmentStorage> randomSegmentIterator;

  /** If the splitfile has a common encryption algorithm, this is it. */
  final byte splitfileSingleCryptoAlgorithm;

  /** If the splitfile has a common encryption key, this is it. */
  final byte[] splitfileSingleCryptoKey;

  /**
   * Forward error correction (FEC) codec configured for this splitfile.
   *
   * <p>The codec is selected from the metadata's {@code SplitfileAlgorithm} and is used when
   * reconstructing missing blocks during segment decoding. It remains constant for the lifetime of
   * a {@code SplitFileFetcherStorage} instance and is read-mostly; callers must treat it as
   * immutable. Implementations may allocate native buffers or other resources inside the codec, so
   * it should be reused rather than recreated for every operation.
   */
  public final FECCodec fecCodec;

  final Ticker ticker;
  final PersistentJobRunner jobRunner;
  final MemoryLimitedJobRunner memoryLimitedJobRunner;

  /**
   * Final length of the downloaded data. *BEFORE* decompression, filtering, etc. I.e., this is the
   * length of the data on disk, which will be written by the StreamGenerator.
   */
  final long finalLength;

  /**
   * Final length of the downloaded data, after decompression. (May change if the data is filtered).
   */
  final long decompressedLength;

  final SplitfileAlgorithm splitfileType;

  /** MIME type etc. Set on construction and passed to onSuccess(). */
  final ClientMetadata clientMetadata;

  /** Decompressors. Set on construction and passed to onSuccess(). */
  final List<COMPRESSOR_TYPE> decompressors;

  /**
   * False = Transient: We are using the RAF as scratch space, we only need to write the blocks and
   * the keys (if we don't keep them in memory). True = Persistent: It must be possible to resume
   * after a node restarting. Ideally, we'd like to be able to recover the download in its entirety
   * without needing any additional information. However, at a minimum we want to be able to
   * continue it while passing in the usual external arguments (FetchContext, parent, etc.).
   */
  final boolean persistent;

  private boolean finishedFetcher;
  private boolean finishedEncoding;
  private boolean cancelled;
  private boolean succeeded;

  /** Errors. For now, this has not persisted. */
  FailureCodeTracker errors;

  final int maxRetries;

  /** Every cooldownTries attempts, a key will enter cooldown and won't be re-tried for a period. */
  final int cooldownTries;

  /** Cooldown lasts this long for each key. */
  final long cooldownLength;

  /** Only set if all segments are in cooldown. */
  private long overallCooldownWakeupTime;

  final CompatibilityMode finalMinCompatMode;

  /** Contains Bloom filters */
  final SplitFileFetcherKeyListener keyListener;

  final RandomSource random;

  // Metadata for the file i.e., stuff we need to be able to efficiently read/write it.
  /** Offset to start of the key lists in bytes */
  final long offsetKeyList;

  /** Offset to start of the segment status in bytes */
  final long offsetSegmentStatus;

  /** Offset to start of the general progress section */
  final long offsetGeneralProgress;

  /** Offset to start of the bloom filters in bytes */
  final long offsetMainBloomFilter;

  /** Offset to start of the per-segment bloom filters in bytes */
  final long offsetSegmentBloomFilters;

  /** Offset to start of the original metadata in bytes */
  final long offsetOriginalMetadata;

  /**
   * Offset to start of the original details in bytes. "Original details" includes the URI to this
   * download (if available), the original URI for the whole download (if available), whether this
   * is the final fetch (it might be a metadata or container fetch), and data from the ultimate
   * client, e.g., the Identifier, whether it is on the Global queue, the client name if it isn't,
   * etc.
   */
  final long offsetOriginalDetails;

  /** Offset to start of the basic settings in bytes */
  final long offsetBasicSettings;

  /** Length of all section checksums */
  final int checksumLength;

  /** Checksum implementation */
  final ChecksumChecker checksumChecker;

  boolean hasCheckedDatastore;
  boolean dirtyGeneralProgress;
  static final long HAS_CHECKED_DATASTORE_FLAG = 1;

  /** Fixed value posted at the end of the file (if plaintext!) */
  static final long END_MAGIC = 0x28b32d99416eb6efL;

  /** Current format version */
  static final int VERSION = 1;

  /**
   * List of segments we need to tryStartDecode() on because their metadata was corrupted on
   * startup.
   */
  List<SplitFileFetcherSegmentStorage> segmentsToTryDecode;

  /**
   * Create a new storage instance backed by a fresh on-disk layout.
   *
   * <p>This constructor interprets the supplied metadata, allocates segment and cross-segment
   * state, initializes Bloom filters and checksums, and wires asynchronous helpers. It does not
   * block on network I/O but may perform bounded file I/O to prepare the persistent structures when
   * {@code persistent} is enabled in {@link SplitFileFetcherStorageInitParams}. On success the
   * instance is ready to be driven by the owning fetcher and will contain computed offsets for all
   * persistent sections.
   *
   * <p>Callers normally place the instance under a coordinating fetcher which drives block request
   * scheduling. Once all segments finish and postconditions are met, the fetcher calls {@link
   * #streamGenerator()} to materialize the final byte stream.
   *
   * @param p immutable parameters, including metadata, factories, and execution helpers, must be
   *     non-null.
   * @throws FetchException when policy validation fails before any network activity begins.
   * @throws MetadataParseException when metadata cannot describe a supported splitfile layout.
   * @throws IOException when on-disk structures cannot be created or verified.
   */
  public SplitFileFetcherStorage(SplitFileFetcherStorageInitParams p)
      throws FetchException, MetadataParseException, IOException {
    // Initialize immutable/basic fields.
    this.fetcher = p.fetcher;
    this.jobRunner = p.exec;
    this.ticker = p.ticker;
    this.memoryLimitedJobRunner = p.memoryLimitedJobRunner;
    this.finalLength = p.metadata.dataLength();
    this.decompressedLength = p.metadata.uncompressedDataLength();
    this.splitfileType = p.metadata.getSplitfileType();
    this.fecCodec = FECCodec.getInstance(splitfileType);
    this.decompressors = p.decompressors;
    this.random = p.random;
    this.errors = new FailureCodeTracker(false);
    this.checksumChecker = p.checker;
    this.checksumLength = p.checker.checksumLength();
    this.persistent = p.persistent;
    this.completeViaTruncation = (p.storageFile != null);
    if (p.decompressors.size() > 1) {
      LOG.error(
          "Multiple decompressors: {} - this is almost certainly a bug",
          p.decompressors.size(),
          new Exception("debug"));
    }
    this.clientMetadata =
        p.clientMetadata == null ? new ClientMetadata() : ClientMetadata.copyOf(p.clientMetadata);

    SplitFileSegmentKeys[] segmentKeys = p.metadata.getSegmentKeys();

    int crossCheckBlocks = p.metadata.getCrossCheckBlocks();

    maxRetries = p.origFetchContext.getMaxSplitfileBlockRetries();
    cooldownTries = p.origFetchContext.getCooldownRetries();
    cooldownLength = p.origFetchContext.getCooldownTime();
    this.splitfileSingleCryptoAlgorithm = p.metadata.getSplitfileCryptoAlgorithm();
    splitfileSingleCryptoKey = p.metadata.getSplitfileCryptoKey();

    // These are approximate values, the number of blocks per segment varies.
    int blocksPerSegment = p.metadata.getDataBlocksPerSegment();
    int checkBlocksPerSegment = p.metadata.getCheckBlocksPerSegment();

    // Accumulate sizes and counts over segments.
    SplitFileFetcherStorageLayout.AccumulatedSizes acc =
        SplitFileFetcherStorageLayout.accumulateSizes(
            segmentKeys,
            crossCheckBlocks,
            splitfileSingleCryptoKey != null,
            checksumLength,
            maxRetries,
            persistent);

    int totalCrossCheckBlocks = segmentKeys.length * crossCheckBlocks;
    long storedBlocksLength;
    long storedCrossCheckBlocksLength;
    if (completeViaTruncation) {
      storedCrossCheckBlocksLength = (long) totalCrossCheckBlocks * CHKBlock.DATA_LENGTH;
      storedBlocksLength = (long) acc.splitfileDataBlocks() * CHKBlock.DATA_LENGTH;
    } else {
      storedCrossCheckBlocksLength = 0;
      storedBlocksLength =
          ((long) acc.splitfileDataBlocks() + totalCrossCheckBlocks) * CHKBlock.DATA_LENGTH;
    }

    int segmentCount = p.metadata.getSegmentCount();
    SplitFileFetcherStorageLayout.validateSegmentCount(segmentCount);

    CompatibilityMode minCompatMode =
        resolveAndReportCompatibility(
            p.metadata,
            p.topDontCompress,
            p.topCompatibilityMode,
            p.origFetchContext,
            blocksPerSegment,
            checkBlocksPerSegment,
            acc.splitfileCheckBlocks());

    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Algorithm: {}, blocks per segment: {}, check blocks per segment: {}, segments: {}, data"
              + " blocks: {}, check blocks: {}",
          splitfileType,
          blocksPerSegment,
          checkBlocksPerSegment,
          segmentCount,
          acc.splitfileDataBlocks(),
          acc.splitfileCheckBlocks());
    }
    segments = new SplitFileFetcherSegmentStorage[segmentCount];
    randomSegmentIterator = new RandomArrayIterator<>(segments);

    long checkLength =
        (acc.splitfileDataBlocks() - (long) segmentCount * crossCheckBlocks) * CHKBlock.DATA_LENGTH;
    SplitFileFetcherStorageLayout.validateCheckLength(checkLength, finalLength);

    byte[] localSalt = new byte[32];
    random.nextBytes(localSalt);

    keyListener =
        new SplitFileFetcherKeyListener(
            fetcher,
            this,
            false,
            localSalt,
            acc.splitfileDataBlocks() + totalCrossCheckBlocks + acc.splitfileCheckBlocks(),
            blocksPerSegment + checkBlocksPerSegment,
            segmentCount);

    finalMinCompatMode = minCompatMode;

    this.offsetKeyList = storedBlocksLength + storedCrossCheckBlocksLength;
    this.offsetSegmentStatus = offsetKeyList + acc.storedKeysLength();

    byte[] generalProgress =
        SplitFileFetcherStoragePersistence.encodeGeneralProgress(
            checksumChecker, hasCheckedDatastore, errors);

    if (persistent) {
      offsetGeneralProgress = offsetSegmentStatus + acc.storedSegmentStatusLength();
      this.offsetMainBloomFilter = offsetGeneralProgress + generalProgress.length;
      this.offsetSegmentBloomFilters =
          offsetMainBloomFilter + keyListener.paddedMainBloomFilterSize();
      this.offsetOriginalMetadata =
          offsetSegmentBloomFilters + keyListener.totalSegmentBloomFiltersSize();
    } else {
      // Don't store anything except the blocks and the key list.
      offsetGeneralProgress =
          offsetMainBloomFilter =
              offsetSegmentBloomFilters = offsetOriginalMetadata = offsetSegmentStatus;
    }

    SplitFileFetcherSegmentsBuilder.SegmentsBuildContext segCtx =
        new SplitFileFetcherSegmentsBuilder.SegmentsBuildContext();
    segCtx.parent = this;
    segCtx.segments = segments;
    segCtx.metadata = p.metadata;
    segCtx.segmentKeys = segmentKeys;
    segCtx.crossCheckBlocks = crossCheckBlocks;
    segCtx.blocksPerSegment = blocksPerSegment;
    segCtx.checkBlocksPerSegment = checkBlocksPerSegment;
    segCtx.origFetchContext = p.origFetchContext;
    segCtx.salt = p.salt;
    segCtx.keysFetching = p.keysFetching;
    segCtx.acc = acc;
    segCtx.storedBlocksLength = storedBlocksLength;
    segCtx.storedCrossCheckBlocksLength = storedCrossCheckBlocksLength;
    segCtx.completeViaTruncation = completeViaTruncation;
    segCtx.persistent = persistent;
    segCtx.hasSplitfileSingleCryptoKey = splitfileSingleCryptoKey != null;
    segCtx.checksumLength = checksumLength;
    SplitFileFetcherSegmentsInit segmentsInit =
        SplitFileFetcherSegmentsBuilder.initSegmentsAndKeys(segCtx);
    this.crossSegments = segmentsInit.crossSegments;

    // Prepare metadata buffers and compute final layout lengths/offsets (assign finals here).
    long totalLength;
    SplitFileFetcherStoragePersistence.PreparedMetadata prepared = null;
    byte[] encodedBasicSettings;
    if (persistent) {
      SplitFileFetchOriginalDetails originalDetails =
          new SplitFileFetchOriginalDetails(p.thisKey, p.origKey, p.clientDetails, p.isFinalFetch);
      SplitFileFetchRetryPolicy retryPolicy =
          new SplitFileFetchRetryPolicy(maxRetries, cooldownTries, cooldownLength);
      prepared =
          SplitFileFetcherStoragePersistence.preparePersistent(
              p.metadata,
              p.tempBucketFactory,
              originalDetails,
              offsetOriginalMetadata,
              checksumChecker,
              retryPolicy);
      offsetOriginalDetails = prepared.offsetOriginalDetails();
      this.offsetBasicSettings = prepared.offsetBasicSettings();
      // Now offsets are final, we can encode the basic settings which embed them.
      encodedBasicSettings =
          encodeBasicSettings(
              acc.splitfileDataBlocks(),
              acc.splitfileCheckBlocks(),
              crossCheckBlocks * segments.length);
      totalLength =
          offsetBasicSettings + encodedBasicSettings.length + 4 + checksumLength + 4 + 4 + 2 + 8;
    } else {
      totalLength = offsetSegmentStatus;
      offsetOriginalDetails = offsetBasicSettings = offsetSegmentStatus;
      encodedBasicSettings = null;
    }

    // Create the actual LockableRandomAccessBuffer
    rafLength = totalLength;
    raf =
        SplitFileFetcherStorageRafFactory.createRafOrThrow(
            p.storageFile, totalLength, p.rafFactory, p.diskSpaceCheckingRAFFactory, random, LOG);
    SplitFileFetcherStoragePersistenceWriter.writeToRaf(
        this, segmentKeys, prepared, encodedBasicSettings, generalProgress, totalLength);
    if (LOG.isDebugEnabled()) LOG.debug("Fetching {} on {} for {}", p.thisKey, this, fetcher);
    initAsyncHelpers();
  }

  /**
   * Resume a persistent storage instance from an existing on-disk format.
   *
   * <p>This constructor validates footer magic, checksums, and version, locates each logical
   * section, and rebuilds segment state and Bloom filters. It also reattaches asynchronous helpers
   * and prepares any pending decoding attempts when segment metadata indicates partial progress.
   * Successful completion means the instance is ready for {@link #start(boolean)} with resume
   * semantics and will reflect on-disk progress accurately.
   *
   * @param p resume parameters, including existing buffer and runtime helpers, must be non-null.
   * @throws IOException when the underlying buffer cannot be read or locked.
   * @throws StorageFormatException when checksums, version, or offsets are invalid.
   * @throws FetchException when resumed state violates fetch policy or limits.
   */
  public SplitFileFetcherStorage(SplitFileFetcherStorageResumeParams p)
      throws IOException, StorageFormatException, FetchException {
    this.persistent = true;
    this.raf = p.raf;
    this.fetcher = p.callback;
    this.ticker = p.ticker;
    this.jobRunner = p.exec;
    this.memoryLimitedJobRunner = p.memoryLimitedJobRunner;
    this.random = p.random;
    this.checksumChecker = p.checker;
    this.checksumLength = p.checker.checksumLength();
    this.maxRetries = p.origContext.getMaxSplitfileBlockRetries();
    this.cooldownTries = p.origContext.getCooldownRetries();
    this.cooldownLength = p.origContext.getCooldownTime();
    // Errors are not persisted currently.
    this.errors = new FailureCodeTracker(false);
    this.completeViaTruncation = p.completeViaTruncation;

    this.rafLength = p.raf.size();
    ParsedBasicSettings parsed =
        SplitFileFetcherStorageResumeReader.readParsedSettings(
            raf, checksumChecker, checksumLength, rafLength, p.completeViaTruncation);

    // Assign parsed values to final fields
    this.splitfileType = parsed.getSplitfileType();
    this.fecCodec = FECCodec.getInstance(splitfileType);
    this.splitfileSingleCryptoAlgorithm = parsed.getSplitfileSingleCryptoAlgorithm();
    this.splitfileSingleCryptoKey = parsed.getSplitfileSingleCryptoKey();
    this.finalLength = parsed.getFinalLength();
    this.decompressedLength = parsed.getDecompressedLength();
    this.clientMetadata = parsed.getClientMetadata();
    this.decompressors = parsed.getDecompressors();
    this.offsetKeyList = parsed.getOffsetKeyList();
    this.offsetSegmentStatus = parsed.getOffsetSegmentStatus();
    this.offsetGeneralProgress = parsed.getOffsetGeneralProgress();
    this.offsetMainBloomFilter = parsed.getOffsetMainBloomFilter();
    this.offsetSegmentBloomFilters = parsed.getOffsetSegmentBloomFilters();
    this.offsetOriginalMetadata = parsed.getOffsetOriginalMetadata();
    this.offsetOriginalDetails = parsed.getOffsetOriginalDetails();
    this.offsetBasicSettings = parsed.getOffsetBasicSettings();
    this.finalMinCompatMode = parsed.getFinalMinCompatMode();

    // Allocate and assign segments array before constructing individual segments.
    this.segments = new SplitFileFetcherSegmentStorage[parsed.getSegmentCount()];
    this.randomSegmentIterator = new RandomArrayIterator<>(segments);
    SplitFileFetcherSegmentsInit segmentsInit =
        SplitFileFetcherSegmentsBuilder.initSegmentsFromStream(
            new SplitFileFetcherSegmentsLoadParams(
                this,
                parsed.getTotalDataBlocks(),
                parsed.getTotalCheckBlocks(),
                parsed.getTotalCrossCheckBlocks(),
                parsed.getSettingsStream(),
                p.completeViaTruncation,
                p.keysFetching,
                this.segments,
                checksumLength,
                splitfileSingleCryptoKey != null,
                offsetKeyList,
                offsetSegmentStatus,
                rafLength));
    this.crossSegments = segmentsInit.crossSegments;
    this.keyListener =
        new SplitFileFetcherKeyListener(
            this, fetcher, segmentsInit.remainingStream, false, p.newSalt);

    SplitFileFetcherStorageRecovery recovery = new SplitFileFetcherStorageRecovery(this);
    recovery.postInitReadSegmentState();
    recovery.readGeneralProgress();
    initAsyncHelpers();
  }

  /**
   * Start the storage layer and enqueue any required recovery work.
   *
   * <p>This method reattaches cross-segment helpers, schedules any deferred decoding attempts, and
   * optionally notifies the fetcher of resume statistics. When key Bloom filters are missing, it
   * triggers asynchronous regeneration and returns {@code false} so the caller does not schedule
   * requests prematurely. It performs no network I/O but may queue background work that later
   * drives request scheduling through callbacks.
   *
   * @param resume {@code true} when resuming purely from disk state without memory snapshots.
   * @return {@code true} when the caller may schedule immediately; {@code false} when callbacks
   *     will schedule later.
   */
  public boolean start(boolean resume) {
    if (resume) onResumeInit();
    SplitFileFetcherStorageRecovery recovery = new SplitFileFetcherStorageRecovery(this);
    recovery.restartCrossSegments();
    recovery.scheduleTryDecodeForBrokenSegments();
    if (keyListener.needsKeys()) return recovery.regenerateKeysAsync();
    return true;
  }

  private void onResumeInit() {
    int splitfileDataBlocks = 0;
    int splitfileCheckBlocks = 0;
    int totalCrossCheckBlocks = 0;
    int succeededBlocks = 0;
    int failedBlocks = 0;
    for (SplitFileFetcherSegmentStorage segment : segments) {
      splitfileDataBlocks += segment.dataBlocks;
      splitfileCheckBlocks += segment.checkBlocks;
      totalCrossCheckBlocks += segment.crossSegmentCheckBlocks;
      succeededBlocks += segment.foundBlocks();
      failedBlocks += segment.failedBlocks();
    }
    fetcher.setSplitfileBlocks(splitfileDataBlocks + totalCrossCheckBlocks, splitfileCheckBlocks);
    fetcher.onResume(succeededBlocks, failedBlocks, clientMetadata, decompressedLength);
  }

  OutputStream checksumOutputStream(OutputStream os) {
    return checksumChecker.checksumWriter(os);
  }

  private byte[] encodeBasicSettings(
      int totalDataBlocks, int totalCheckBlocks, int totalCrossCheckBlocks) {
    return SplitFileFetcherStorageSettingsCodec.encodeBasicSettings(
        this, totalDataBlocks, totalCheckBlocks, totalCrossCheckBlocks);
  }

  AutoCloseableRafLock autoLockOpen() throws IOException {
    return new AutoCloseableRafLock(raf.lockOpen());
  }

  static final class AutoCloseableRafLock implements AutoCloseable {
    private final RAFLock lock;

    AutoCloseableRafLock(RAFLock lock) {
      this.lock = lock;
    }

    @Override
    public void close() {
      lock.unlock();
    }
  }

  private CompatibilityMode resolveAndReportCompatibility(
      Metadata metadata,
      boolean topDontCompress,
      short topCompatibilityMode,
      FetchContext origFetchContext,
      int blocksPerSegment,
      int checkBlocksPerSegment,
      int splitfileCheckBlocks)
      throws FetchException, MetadataParseException {
    CompatibilityMode minCompatMode = metadata.getMinCompatMode();
    CompatibilityMode maxCompatMode = metadata.getMaxCompatMode();

    if (splitfileType == SplitfileAlgorithm.NONREDUNDANT && splitfileCheckBlocks > 0) {
      LOG.error(
          "Splitfile type is SPLITFILE_NONREDUNDANT yet {} check blocks found!! : {}",
          splitfileCheckBlocks,
          this);
      throw new FetchException(
          FetchExceptionMode.INVALID_METADATA,
          "Splitfile type is non-redundant yet have " + splitfileCheckBlocks + " check blocks");
    }
    switch (splitfileType) {
      case NONREDUNDANT -> {
        // ok
      }
      case ONION_STANDARD -> {
        boolean dontCompress = decompressors.isEmpty();
        if (topCompatibilityMode != 0) {
          if (minCompatMode == CompatibilityMode.COMPAT_UNKNOWN
              || !(minCompatMode.code > topCompatibilityMode
                  || maxCompatMode.code < topCompatibilityMode)) {
            if (!CompatibilityMode.hasCode(topCompatibilityMode)) {
              throw new FetchException(
                  FetchExceptionMode.INVALID_METADATA,
                  "Top compatibility mode is incompatible with detected compatibility mode");
            }
            minCompatMode = maxCompatMode = CompatibilityMode.byCode(topCompatibilityMode);
            dontCompress = topDontCompress;
          } else {
            throw new FetchException(
                FetchExceptionMode.INVALID_METADATA,
                "Top compatibility mode is incompatible with detected compatibility mode");
          }
        }
        byte[] customKey = metadata.getCustomSplitfileKey();
        fetcher.onSplitfileCompatibilityMode(
            minCompatMode,
            maxCompatMode,
            (customKey == null || customKey.length == 0) ? null : customKey,
            dontCompress,
            true,
            topCompatibilityMode != 0);
        validateBlocksPerSegmentLimit(origFetchContext, blocksPerSegment, checkBlocksPerSegment);
      }
      default -> throw new MetadataParseException("Unknown splitfile format: " + splitfileType);
    }
    return minCompatMode;
  }

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

  /**
   * Return the priority class forwarded to the request scheduler.
   *
   * <p>The class originates from the owning fetcher and influences how aggressively requests are
   * scheduled relative to other work. The value is treated as a stable attribute of the fetch and
   * is safe to query frequently; this method performs no synchronization beyond reading the cached
   * field. Callers should avoid interpreting the numeric value directly and instead pass it through
   * scheduler APIs that understand the range.
   *
   * @return the fetcher's short priority class used by scheduling heuristics.
   */
  public short getPriorityClass() {
    return fetcher.getPriorityClass();
  }

  /**
   * Record that a segment completed successfully and evaluate overall completion.
   *
   * <p>When a segment finishes decoding, the storage checks whether all other segments have also
   * finished successfully. If so, completion is signaled and the success callback is scheduled. If
   * the fetcher requested a binary blob or truncation is in use, completion may be deferred until
   * post-processing is done. This method is safe to call multiple times for the same segment and
   * will only trigger completion once.
   *
   * @param segment segment that just reported success, used only for diagnostics.
   */
  public void finishedSuccess(SplitFileFetcherSegmentStorage segment) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "finishedSuccess on {} from {} for {}", this, segment, fetcher, new Exception("debug"));
    if (!(completeViaTruncation || fetcher.wantBinaryBlob())) maybeComplete();
  }

  private void maybeComplete() {
    if (allSucceeded()) {
      callSuccessOffThread();
    } else if (allFinished() && !allSucceeded()) {
      // Some failed.
      fail(new FetchException(FetchExceptionMode.SPLITFILE_ERROR, errors));
    }
  }

  private void callSuccessOffThread() {
    jobRunner.queueNormalOrDrop(
        _ -> {
          synchronized (SplitFileFetcherStorage.this) {
            // Race conditions are possible, make sure we only call it once.
            if (succeeded) return false;
            succeeded = true;
          }
          fetcher.onSuccess();
          return true;
        });
  }

  private boolean allSucceeded() {
    for (SplitFileFetcherSegmentStorage segment : segments) {
      if (!segment.hasSucceeded()) return false;
    }
    return true;
  }

  /**
   * Create a {@link StreamGenerator} that materializes the final decoded data stream.
   *
   * <p>The returned generator emits data blocks for all segments in logical order and applies any
   * required transformations (for example, decompression) declared by the metadata. The generator
   * performs blocking file reads and may hold the RAF lock while streaming, so callers should
   * invoke it off the request-selection thread and avoid concurrent mutation of segment state. It
   * is intended for one logical consumer at a time; create a fresh generator for each output target
   * if repeated streaming is required.
   *
   * <pre>{@code
   * // Example: write the reconstructed bytes to an OutputStream
   * var gen = storage.streamGenerator();
   * gen.writeTo(outputStream, clientContext);
   * }</pre>
   *
   * @return a generator that reads from underlying storage and writes the complete payload on
   *     demand; it is not thread-safe.
   */
  public StreamGenerator streamGenerator() {
    // Truncation optimization can be added in the future if safe.
    return new StreamGenerator() {

      @Override
      public void writeTo(OutputStream os, ClientContext context) throws IOException {
        try (var _ = autoLockOpen()) {
          writeAllSegmentsToStream(os);
        }
      }

      @Override
      public long size() {
        return finalLength;
      }
    };
  }

  private void writeAllSegmentsToStream(OutputStream os) {
    try {
      for (SplitFileFetcherSegmentStorage segment : segments) {
        segment.writeToInner(os);
      }
      os.close();
    } catch (Exception t) {
      LOG.error("Failed to write stream: {}", t, t);
    }
  }

  // Matches NativeThread.PriorityLevel.LOW_PRIORITY.value + 1.
  static final int REGENERATE_KEYS_PRIORITY = 4;
  static final long LAZY_WRITE_METADATA_DELAY = 5L * 60 * 1000;

  private PersistentJob writeMetadataJob;

  private void writeGeneralProgressInner() {
    synchronized (this) {
      if (!dirtyGeneralProgress) return;
      dirtyGeneralProgress = false;
    }
    byte[] generalProgress =
        SplitFileFetcherStoragePersistence.encodeGeneralProgress(
            checksumChecker, hasCheckedDatastore, errors);
    try {
      raf.pwrite(offsetGeneralProgress, generalProgress, 0, generalProgress.length);
    } catch (IOException e) {
      failOnDiskError(e);
    }
  }

  private void initAsyncHelpers() {
    this.writeMetadataJob =
        _ -> {
          try {
            if (isFinishing()) return false;
            RAFLock lock = raf.lockOpen();
            try {
              for (SplitFileFetcherSegmentStorage segment : segments) {
                segment.writeMetadata(false);
              }
              keyListener.maybeWriteMainBloomFilter(offsetMainBloomFilter);
            } finally {
              lock.unlock();
            }
            writeGeneralProgressInner();
            return false;
          } catch (IOException e) {
            if (isFinishing()) return false;
            LOG.error("Failed writing metadata for {}: {}", SplitFileFetcherStorage.this, e, e);
            return false;
          }
        };
    this.wrapLazyWriteMetadata = () -> jobRunner.queueNormalOrDrop(writeMetadataJob);
  }

  private Runnable wrapLazyWriteMetadata;

  /**
   * Schedule a best-effort metadata writing.
   *
   * <p>When running in persistent mode, metadata changes are checkpointed asynchronously to reduce
   * contention and I/O overhead. Calls may coalesce when invoked in quick succession, so it is safe
   * to call this after each state change without creating extra disk churn. In non-persistent mode
   * this method is a no-op. The writing occurs off-thread and does not guarantee immediate
   * durability; callers that need a synchronous flush should use higher-level shutdown paths.
   */
  public void lazyWriteMetadata() {
    if (!persistent) return;
    if (LAZY_WRITE_METADATA_DELAY > 0 && !isFinishing()) {
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
   * Mark the associated fetcher as finished and trigger resource cleanup when eligible.
   *
   * <p>When both the fetcher and the encoder have finished (and truncation is not pending), the
   * storage closes its backing file off-thread. Repeated calls are safe and ignored after the first
   * transition. If truncation is requested, cleanup is deferred until encoding completes and the
   * truncation path has run, ensuring the RAF remains available for late writes.
   */
  public void finishedFetcher() {
    synchronized (this) {
      if (finishedFetcher) {
        if (LOG.isDebugEnabled()) LOG.debug("Already finishedFetcher");
        return;
      }
      finishedFetcher = true;
      if (completeViaTruncation && !cancelled) return; // Ignore.
      if (!finishedEncoding) return;
    }
    closeOffThread();
  }

  /** Called on a normal non-truncation completion. Frees the storage file off-thread. */
  private void closeOffThread() {
    jobRunner.queueNormalOrDrop(
        _ -> {
          // ATOMICITY/DURABILITY: This will run after the checkpoint after completion.
          // So after restarting, even if the checkpoint failed, we will be in a valid state.
          // This is why this is queue() not queueInternal().
          close();
          return true;
        });
  }

  private void finishedEncoding() {
    FinishState state = computeFinishEncodingState();
    if (state.alreadyFinished()) return;
    if (state.lateCompletion()) {
      if (allFinished() && !allSucceeded()) {
        fail(new FetchException(FetchExceptionMode.SPLITFILE_ERROR, errors));
      } else {
        if (completeViaTruncation) raf.close();
        maybeComplete();
        return;
      }
    }
    if (state.waitingForFetcher()) return;
    closeOffThread();
  }

  private record FinishState(
      boolean alreadyFinished, boolean lateCompletion, boolean waitingForFetcher) {}

  private FinishState computeFinishEncodingState() {
    boolean alreadyFinished = false;
    boolean lateCompletion = false;
    boolean waitingForFetcher = false;
    synchronized (this) {
      if (finishedEncoding) {
        if (LOG.isDebugEnabled()) LOG.debug("Already finishedEncoding");
        alreadyFinished = true;
      } else {
        if (LOG.isDebugEnabled()) LOG.debug("Finished encoding");
        finishedEncoding = true;
        if (!cancelled && (completeViaTruncation || fetcher.wantBinaryBlob()) && !succeeded) {
          lateCompletion = true;
        } else if (!cancelled) {
          waitingForFetcher = !finishedFetcher;
        }
      }
    }
    return new FinishState(alreadyFinished, lateCompletion, waitingForFetcher);
  }

  /**
   * Shutdown and free resources. CONCURRENCY: Caller is responsible for making sure this is not
   * called on a MemoryLimitedJob thread.
   */
  void close() {
    if (LOG.isDebugEnabled()) LOG.debug("Finishing {} for {}", this, fetcher);
    raf.close();
    raf.free();
    fetcher.onClosed();
  }

  /**
   * Called when a segment has finished encoding. It is possible that it has simply restarted; it is
   * not guaranteed to have encoded all blocks etc. But we still need the callback in case e.g., we
   * are in the process of failing, and can't proceed until all the encoding jobs have finished.
   */
  void finishedEncoding(SplitFileFetcherSegmentStorage segment) {
    if (LOG.isDebugEnabled())
      LOG.debug("Segment decode completed {} for {} for {}", segment, this, fetcher);
    if (!allFinished()) return;
    finishedEncoding();
  }

  /**
   * Called when a cross-segment has finished decoding. It doesn't necessarily have a "finished"
   * state, except if it was canceled.
   */
  void finishedEncoding(SplitFileFetcherCrossSegmentStorage segment) {
    if (LOG.isDebugEnabled())
      LOG.debug("Cross-segment decode completed {} for {} for {}", segment, this, fetcher);
    if (!allFinished()) return;
    finishedEncoding();
  }

  private boolean allFinished() {
    // First, are any of the segments still working, that is, are they able to send requests,
    // or are they decoding/encoding?
    for (SplitFileFetcherSegmentStorage segment : segments) {
      if (!segment.isFinished()) return false;
    }
    // We cannot proceed unless none of the cross-segments is decoding.
    if (crossSegments != null) {
      for (SplitFileFetcherCrossSegmentStorage segment : crossSegments) {
        if (segment.isDecoding()) return false;
      }
    }
    return true;
  }

  /**
   * Fail the overall request and notify the callback asynchronously.
   *
   * <p>Failure is posted to the job runner to avoid deadlocks with request-selection or decode
   * threads. The storage remains valid until the callback initiates shutdown, allowing callers to
   * inspect error codes and progress. This method does not attempt retries or cancellation on its
   * own; it simply forwards the provided {@link FetchException} to the fetcher.
   *
   * @param e failure cause describing mode and context; must not be {@code null}.
   */
  public void fail(final FetchException e) {
    if (LOG.isDebugEnabled()) LOG.debug("Failing {} with error {} and codes {}", this, e, errors);
    jobRunner.queueNormalOrDrop(
        _ -> {
          fetcher.fail(e);
          return true;
        });
  }

  /**
   * Abort the splitfile when a segment exhausts its retry budget.
   *
   * <p>This helper converts the condition into a consolidated {@link FetchException} and routes it
   * through {@link #fail(FetchException)} so shutdown happens consistently. It does not mutate the
   * segment itself; the segment state is expected to already reflect the terminal failure
   * condition. Callers typically invoke this after a retry budget check fails.
   *
   * @param segment segment that can no longer make progress, used only for logging.
   */
  public void failOnSegment(SplitFileFetcherSegmentStorage segment) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Segment {} exhausted retries; failing splitfile {}",
          segment.segNo,
          SplitFileFetcherStorage.this);
    }
    fail(new FetchException(FetchExceptionMode.SPLITFILE_ERROR, errors));
  }

  /**
   * Report a non-recoverable disk I/O error to the fetcher.
   *
   * <p>Any failure during metadata or block persistence is considered fatal for the session. The
   * notification occurs off-thread to avoid blocking callers inside I/O paths. The storage does not
   * attempt to retry the failing operation; recovery decisions are left to the fetcher and its
   * surrounding context.
   *
   * @param e I/O exception observed while reading or writing persistent state.
   */
  public void failOnDiskError(final IOException e) {
    LOG.error("Failing on disk error: {}", e, e);
    jobRunner.queueNormalOrDrop(
        _ -> {
          fetcher.failOnDiskError(e);
          return true;
        });
  }

  /**
   * Report a checksum verification failure to the fetcher.
   *
   * <p>The storage zeroes the affected bytes and surfaces the failure via the callback. Depending
   * on policy, the fetcher may propagate the error or attempt recovery using redundant blocks. This
   * method only reports the condition; it does not initiate decoding or rebuilds directly.
   *
   * @param e checksum failure raised when verifying a checksummed section from disk.
   */
  public void failOnDiskError(final ChecksumFailedException e) {
    LOG.error("Failing on unrecoverable corrupt data: {}", e, e);
    jobRunner.queueNormalOrDrop(
        _ -> {
          fetcher.failOnDiskError(e);
          return true;
        });
  }

  /**
   * Count the number of not-yet-fetched keys across all segments.
   *
   * <p>The value includes keys that are currently cooling down or temporarily skipped. It is
   * computed from the in-memory segment state and does not perform disk I/O. Use this for progress
   * estimation rather than exact completion criteria; failed blocks and delayed retries can cause
   * the count to oscillate.
   *
   * @return a non-negative count representing remaining work before decode can proceed.
   */
  public long countUnfetchedKeys() {
    long total = 0;
    for (SplitFileFetcherSegmentStorage segment : segments) total += segment.countUnfetchedKeys();
    return total;
  }

  /**
   * List keys that have not yet been fetched.
   *
   * <p>The returned array may be empty but never {@code null}. Keys are provided for diagnostic or
   * scheduling purposes and are not guaranteed to be immutable; callers should copy if retaining.
   * On I/O failure the storage reports the disk error and returns an empty array.
   *
   * @return a possibly empty snapshot of outstanding {@link Key} instances.
   */
  public Key[] listUnfetchedKeys() {
    try {
      ArrayList<Key> keys = new ArrayList<>();
      for (SplitFileFetcherSegmentStorage segment : segments) segment.getUnfetchedKeys(keys);
      return keys.toArray(new Key[0]);
    } catch (IOException e) {
      failOnDiskError(e);
      return new Key[0];
    }
  }

  /**
   * Count keys that are immediately eligible to send based on cooldown and retry limits.
   *
   * <p>The result depends on the current time, retry counters, and segment-level cooldown. It is
   * intended for request schedulers to estimate near-term concurrency rather than for strict
   * accounting. The count is computed without disk I/O and may change rapidly as cooldowns expire.
   *
   * @return the number of keys that can be turned into outbound requests without waiting.
   */
  public long countSendableKeys() {
    long total = 0;
    for (SplitFileFetcherSegmentStorage segment : segments) total += segment.countSendableKeys();
    return total;
  }

  /**
   * Lightweight handle identifying a concrete block within a specific segment.
   *
   * <p>Instances are stable identifiers used by schedulers and callbacks to correlate request
   * outcomes with the storage state. The handle is immutable and embeds the owning storage, the
   * segment index, and the block index, so it can be used as a map key or queue token without
   * additional lookups. It is not a cryptographic key; instead it is a positional reference that
   * can be resolved to a {@link ClientKey} through {@link SplitFileFetcherStorage#getKey}. Equality
   * and hash semantics incorporate the storage instance to avoid accidental collisions across
   * concurrent fetches.
   */
  public static final class SplitFileFetcherStorageKey
      implements SendableRequestItem, SendableRequestItemKey {

    /**
     * Create a key handle for the given block and segment.
     *
     * <p>The constructor does not validate indices against segment bounds; callers must supply
     * values obtained from segment state or scheduling helpers. The resulting instance is immutable
     * and can be safely cached or used as a map key for the lifetime of the storage.
     *
     * @param n a zero-based block index within the segment must be in range.
     * @param segNo a zero-based segment index for the owning storage must be valid.
     * @param storage owning storage instance used for lookups and equality; must be non-null.
     */
    public SplitFileFetcherStorageKey(int n, int segNo, SplitFileFetcherStorage storage) {
      this.blockNumber = n;
      this.segmentNumber = segNo;
      this.get = storage;
      hashCode = initialHashCode();
    }

    final int blockNumber;
    final int segmentNumber;
    final SplitFileFetcherStorage get;
    final int hashCode;

    /**
     * Emit a debug dump of this key's computed request state.
     *
     * <p>This implementation intentionally performs no work because the storage key carries only
     * positional identifiers and has no derived state to emit. The method exists to satisfy the
     * request-item interface and is safe to call from diagnostics or tests. Callers should not rely
     * on side effects or output from this method.
     */
    @Override
    public void dump() {
      // Ignore.
    }

    /**
     * Convert this handle into a request-layer key.
     *
     * <p>This implementation returns {@code this} because the storage key already satisfies the
     * request-layer contract. It avoids allocation and preserves identity semantics, which allows
     * schedulers to compare or cache keys without additional wrapping. The returned instance is
     * immutable for the lifetime of the storage.
     *
     * @return this instance as an immutable {@link SendableRequestItemKey} for scheduling.
     */
    @Override
    public SendableRequestItemKey getKey() {
      return this;
    }

    /**
     * Value equality based on segment and block indices.
     *
     * <p>Equality also requires the same owning storage instance, preventing collisions between
     * concurrent fetches that may share segment numbering. This method is consistent with {@link
     * #hashCode()} and is safe for use in hash-based collections. It performs a fast reference and
     * primitive comparison without allocations.
     *
     * @param o candidate object to compare against this key for equality.
     * @return {@code true} when the two keys identify the same storage block.
     */
    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (!(o instanceof SplitFileFetcherStorageKey k)) return false;
      return k.blockNumber == blockNumber && k.segmentNumber == segmentNumber && k.get == get;
    }

    /**
     * Hash code derived from the segment and block indices.
     *
     * <p>The hash includes the owning storage reference to remain consistent with {@link #equals}.
     * It is computed once at construction time and cached, so repeated calls are inexpensive. The
     * value is stable for the lifetime of this key. No randomness is involved.
     *
     * @return a stable hash suitable for hash-based collections and caches.
     */
    @Override
    public int hashCode() {
      return hashCode;
    }

    private int initialHashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + blockNumber;
      result = prime * result + ((get == null) ? 0 : get.hashCode());
      result = prime * result + segmentNumber;
      return result;
    }

    /**
     * Human‑readable form for logging and diagnostics.
     *
     * <p>The representation includes the segment and block indices and is intended for logs and
     * debugging output. The exact format is not guaranteed to remain stable, so callers should not
     * parse the string or depend on it for program logic. The output never includes key material or
     * payload data.
     *
     * @return a concise string containing the segment and block numbers.
     */
    @Override
    public String toString() {
      return "SplitFileFetcherStorageKey:" + segmentNumber + ":" + blockNumber;
    }
  }

  /**
   * Choose a random eligible key from non-decoding, non-finished segments.
   *
   * <p>The selection uses a time‑varying seed to distribute requests and avoids segments currently
   * decoding or ineligible due to cooldown/retry constraints. The method synchronizes on the
   * segment iterator to keep the selection state consistent and may scan multiple segments before
   * finding a candidate. Returns {@code null} when no key is presently sendable.
   *
   * @return a randomly selected {@link SplitFileFetcherStorageKey} or {@code null} when none is
   *     available.
   */
  public SplitFileFetcherStorageKey chooseRandomKey() {
    // Consider using SimpleBlockChooser to prefer lowest-retry-count from each segment.
    synchronized (this) {
      if (finishedFetcher) return null;
    }
    // Generally segments are fairly well-balanced, so we can usually pick a random segment
    // then a random key from it.
    // Optimization idea: one SplitFileFetcherGet per segment (as in older code) could improve
    // scalability.
    synchronized (randomSegmentIterator) {
      randomSegmentIterator.reset(random);
      while (randomSegmentIterator.hasNext()) {
        SplitFileFetcherSegmentStorage segment = randomSegmentIterator.next();
        int ret = segment.chooseRandomKey();
        if (ret != -1) {
          return new SplitFileFetcherStorageKey(ret, segment.segNo, this);
        }
      }
    }
    return null;
  }

  /** Cancel the download, stop all FEC decoding, and call close() off-thread when done. */
  void cancel() {
    synchronized (this) {
      cancelled = true;
    }
    for (SplitFileFetcherSegmentStorage segment : segments) segment.cancel();
    if (crossSegments != null) {
      for (SplitFileFetcherCrossSegmentStorage segment : crossSegments) segment.cancel();
    }
  }

  /**
   * Callback invoked after checking the local datastore for a candidate key.
   *
   * <p>When a check produces a definitive result, the storage updates segment state and may
   * schedule additional work. The method runs off-thread to avoid blocking request selection. It
   * increments the appropriate failure counters and notifies each segment that datastore probing
   * has completed so retries can proceed. If all segments are already finished, the callback is a
   * no-op.
   */
  public void finishedCheckingDatastoreOnLocalRequest() {
    // At this point, all the blocks will have been processed.
    if (hasFinished()) return; // Don't need to do anything.
    this.errors.inc(FetchExceptionMode.ALL_DATA_NOT_FOUND);
    for (SplitFileFetcherSegmentStorage segment : segments) {
      segment.onFinishedCheckingDatastoreNoFetch();
    }
    maybeComplete();
  }

  synchronized boolean hasFinished() {
    return cancelled || finishedFetcher;
  }

  synchronized boolean isFinishing() {
    return cancelled || finishedFetcher || finishedEncoding;
  }

  /**
   * Record a non-fatal failure for a specific block request.
   *
   * <p>The error is accumulated in the failure tracker, and the key is made retryable according to
   * the configured policy. Persistent sessions schedule a metadata checkpoint. Callers should only
   * invoke this for failures that may be retried; terminal failures should go through {@link
   * #fail(FetchException)} or {@link #failOnSegment(SplitFileFetcherSegmentStorage)}.
   *
   * @param key handle whose request failed, used to locate segment and block.
   * @param fe failure reason including mode and context for tracking.
   */
  public void onFailure(SplitFileFetcherStorageKey key, FetchException fe) {
    if (LOG.isDebugEnabled())
      LOG.debug("Failure: {} for block {} for {}", fe.mode, key.blockNumber, key.segmentNumber);
    synchronized (this) {
      if (cancelled || finishedFetcher) return;
      dirtyGeneralProgress = true;
    }
    errors.inc(fe.getMode());
    SplitFileFetcherSegmentStorage segment = segments[key.segmentNumber];
    segment.onNonFatalFailure(key.blockNumber);
    lazyWriteMetadata();
  }

  /**
   * Resolve the client‑layer key for the given handle.
   *
   * <p>The lookup reads segment key data, so it may perform disk I/O and acquire the RAF lock. On
   * I/O failure the storage reports a disk error and returns {@code null}. The call does not change
   * the segment state. Callers should treat the returned {@link ClientKey} as read-only.
   *
   * @param key handle identifying a block, usually from {@link #chooseRandomKey()}.
   * @return client key for the block, or {@code null} on I/O failure.
   */
  public ClientKey getKey(SplitFileFetcherStorageKey key) {
    try {
      return segments[key.segmentNumber].getSegmentKeys().getKey(key.blockNumber, null, false);
    } catch (IOException e) {
      this.failOnDiskError(e);
      return null;
    }
  }

  /**
   * Maximum number of per‑block retries permitted by policy.
   *
   * <p>The limit is derived from the originating {@link FetchContext} and remains fixed for the
   * lifetime of the storage. When a block exceeds this count, its segment transitions to a failure
   * state and the overall fetch eventually fails. A value of {@code -1} indicates unlimited
   * retries.
   *
   * @return a non‑negative limit, or {@code -1} for unlimited retries.
   */
  public int maxRetries() {
    return maxRetries;
  }

  /**
   * Notify the fetcher that a block has permanently failed.
   *
   * <p>The notification is posted asynchronously to keep request-selection threads responsive. It
   * does not modify the storage state directly; callers should ensure segment bookkeeping has
   * already transitioned the block into a terminal state before invoking this callback. The fetcher
   * may coalesce multiple calls.
   */
  public void failedBlock() {
    jobRunner.queueNormalOrDrop(
        _ -> {
          fetcher.onFailedBlock();
          return false;
        });
  }

  /**
   * Indicate whether the final block may omit padding due to compatibility mode.
   *
   * <p>Some legacy compatibility modes allow a short final block without padding. Callers use this
   * signal to decide whether to enforce padding checks during verification or decoding. The value
   * is derived from the stored minimum compatibility mode and does not change after construction.
   *
   * @return {@code true} when padding is not guaranteed for the last block.
   */
  public boolean lastBlockMightNotBePadded() {
    return (finalMinCompatMode == CompatibilityMode.COMPAT_UNKNOWN
        || finalMinCompatMode.code < CompatibilityMode.COMPAT_1416.code);
  }

  /**
   * Called after a corruption recovery path has restarted the session.
   *
   * <p>Clears cooldown if appropriate and relays a notification to the fetcher on a background
   * thread. This method is used when metadata recovery or key regeneration succeeds, allowing the
   * fetcher to resume scheduling without manual intervention. It does not re-run validation; it
   * only signals that recovery work has completed.
   */
  public void restartedAfterDataCorruption() {
    jobRunner.queueNormalOrDrop(
        _ -> {
          maybeClearCooldown();
          fetcher.restartedAfterDataCorruption();
          return false;
        });
  }

  /**
   * Separate lock for cooldown operations, which must be serialized. Must be taken *BEFORE* segment
   * locks.
   */
  private final Object cooldownLock = new Object();

  /** Called when a segment goes into overall cooldown. */
  void increaseCooldown(final long cooldownTime) {
    // Risky locking-wise, so run as a separate job.
    jobRunner.queueNormalOrDrop(
        _ -> {
          long now = System.currentTimeMillis();
          long wakeupTime;
          synchronized (cooldownLock) {
            if (cooldownTime < now) return false;
            if (overallCooldownWakeupTime > now) return false; // Wait for it to wake up.
            wakeupTime = Long.MAX_VALUE;
            for (SplitFileFetcherSegmentStorage segment : segments) {
              long segmentTime = segment.getOverallCooldownTime();
              if (segmentTime < now) return false;
              wakeupTime = Math.min(segmentTime, wakeupTime);
            }
            overallCooldownWakeupTime = wakeupTime;
          }
          fetcher.reduceCooldown(wakeupTime);
          return false;
        });
  }

  // Removed unused segment parameter overload; callers should use single-arg variant.

  /**
   * Clear global cooldown when all segments have exited their individual cooldown windows.
   *
   * <p>This is safe to call frequently; it performs inexpensive checks and posts to the fetcher
   * when the global flag changes. The method synchronizes on the cooldown lock and will reset the
   * global wakeup time only when every segment reports a cleared cooldown. It does not schedule
   * requests directly; that remains the fetcher's responsibility.
   */
  public void maybeClearCooldown() {
    synchronized (cooldownLock) {
      if (overallCooldownWakeupTime == 0 || overallCooldownWakeupTime < System.currentTimeMillis())
        return;
      overallCooldownWakeupTime = 0;
    }
    fetcher.clearCooldown();
  }

  /**
   * Return the earliest time at which requests should resume after cooldown.
   *
   * <p>Returns {@code -1} when the overall request has finished. Otherwise, returns {@code 0} when
   * there is no pending cooldown or a future epoch millisecond timestamp to wait until. The method
   * updates the cached wakeup time to clear stale values and is safe to call from scheduling
   * threads that only hold the request-selection lock.
   *
   * @param now the current epoch time in milliseconds used to clamp stale values.
   * @return negative one if finished, zero if no cooldown, else wakeup time.
   */
  public long getCooldownWakeupTime(long now) {
    // LOCKING: hasFinished() uses (this), separate from cooldownLock.
    // It is safe to use both here (on the request selection thread), one after the other.
    if (hasFinished()) return -1;
    synchronized (cooldownLock) {
      if (overallCooldownWakeupTime < now) overallCooldownWakeupTime = 0;
      return overallCooldownWakeupTime;
    }
  }

  // Operations with checksums and storage access.

  void preadChecksummed(long fileOffset, byte[] buf, int offset, int length)
      throws IOException, ChecksumFailedException {
    byte[] checksumBuf = new byte[checksumLength];
    try (var _ = autoLockOpen()) {
      raf.pread(fileOffset, buf, offset, length);
      raf.pread(fileOffset + length, checksumBuf, 0, checksumLength);
    }
    if (!checksumChecker.checkChecksum(buf, offset, length, checksumBuf)) {
      for (int i = offset; i < offset + length; i++) {
        buf[i] = 0;
      }
      throw new ChecksumFailedException();
    }
  }

  byte[] preadChecksummedWithLength(long fileOffset)
      throws IOException, ChecksumFailedException, StorageFormatException {
    byte[] checksumBuf = new byte[checksumLength];
    byte[] lengthBuf = new byte[8];
    byte[] buf;
    int length;
    try (var _ = autoLockOpen()) {
      raf.pread(fileOffset, lengthBuf, 0, lengthBuf.length);
      long len = new DataInputStream(new ByteArrayInputStream(lengthBuf)).readLong();
      if (len + fileOffset > rafLength || len > Integer.MAX_VALUE || len < 0)
        throw new StorageFormatException("Bogus length " + len);
      length = (int) len;
      buf = new byte[length];
      raf.pread(fileOffset + lengthBuf.length, buf, 0, length);
      raf.pread(fileOffset + length + lengthBuf.length, checksumBuf, 0, checksumLength);
    }
    if (!checksumChecker.checkChecksum(buf, 0, length, checksumBuf)) {
      for (int i = 0; i < length; i++) {
        buf[i] = 0;
      }
      throw new ChecksumFailedException();
    }
    return buf;
  }

  /**
   * Create an OutputStream that we can write formatted data to of a specific length. On close(), it
   * checks that the length is as expected, computes the checksum, and writes the data to the
   * specified position in the file.
   *
   * @param fileOffset The position in the file (raf) of the first byte.
   * @param length The length, including checksum, of the data to be written.
   * @return a non-null OutputStream that buffers content, verifies the exact expected length on
   *     {@code close()}, computes the checksum, and writes the payload plus checksum at {@code
   *     fileOffset}. The caller owns and must close the stream to persist changes.
   */
  OutputStream writeChecksummedTo(final long fileOffset, final int length) {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream(length);
    OutputStream cos = checksumOutputStream(baos);
    return new OutputStream() {
      @Override
      public void write(int b) throws IOException {
        cos.write(b);
      }

      @Override
      public void write(byte @NotNull [] b, int off, int len) throws IOException {
        cos.write(b, off, len);
      }

      @Override
      public void flush() throws IOException {
        cos.flush();
      }

      @Override
      public void close() throws IOException {
        cos.close();
        byte[] buf = baos.toByteArray();
        if (buf.length != length)
          throw new IllegalStateException(
              "Wrote wrong number of bytes: " + buf.length + " should be " + length);
        raf.pwrite(fileOffset, buf, 0, length);
      }
    };
  }

  RAFLock lockRAFOpen() throws IOException {
    return raf.lockOpen();
  }

  void writeBlock(SplitFileFetcherSegmentStorage segment, int slotNumber, byte[] data)
      throws IOException {
    raf.pwrite(segment.blockOffset(slotNumber), data, 0, data.length);
  }

  byte[] readBlock(SplitFileFetcherSegmentStorage segment, int slotNumber) throws IOException {
    long offset = segment.blockOffset(slotNumber);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Reading block {} for {}/{} from {} RAF length is {}",
          slotNumber,
          segment.segNo,
          segments.length,
          offset,
          raf.size());
    byte[] buf = new byte[CHKBlock.DATA_LENGTH];
    raf.pread(offset, buf, 0, buf.length);
    return buf;
  }

  /** Needed for resuming. */
  LockableRandomAccessBuffer getRAF() {
    return raf;
  }

  /**
   * Mark that the local store has been checked at least once during this session.
   *
   * <p>This updates the in-memory flag, marks general progress as dirty, and writes metadata
   * immediately when persistence is enabled. The call is synchronized to ensure visibility across
   * scheduler threads. Callers should pass the same {@link ClientContext} used for other storage
   * checkpoint calls.
   *
   * @param context execution context available when the datastore check completed.
   */
  public synchronized void setHasCheckedStore(ClientContext context) {
    hasCheckedDatastore = true;
    dirtyGeneralProgress = true;
    if (!persistent) return;
    writeMetadataJob.run(context);
  }

  /**
   * Whether a local datastore check has been performed in this session.
   *
   * <p>The flag is updated by {@link #setHasCheckedStore(ClientContext)} and is not persisted for
   * transient sessions. It can be polled by schedulers to decide whether a datastore sweep should
   * be attempted again after restarts. The value is read without additional I/O and is safe to
   * query frequently.
   *
   * @return {@code true} once a datastore check has completed in this session.
   */
  public synchronized boolean hasCheckedStore() {
    return hasCheckedDatastore;
  }

  void onShutdown(ClientContext context) {
    writeMetadataJob.run(context);
  }
}

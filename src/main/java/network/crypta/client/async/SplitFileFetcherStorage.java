package network.crypta.client.async;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
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
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.crypt.HashType;
import network.crypta.crypt.MultiHashOutputStream;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.ClientKey;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.Key;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.node.SendableRequestItem;
import network.crypta.node.SendableRequestItemKey;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.RandomArrayIterator;
import network.crypta.support.Ticker;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBuffer.RAFLock;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.NativeThread;
import network.crypta.support.io.StorageFormatException;
import network.crypta.support.math.MersenneTwister;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Stores the state for a SplitFileFetcher, persisted to a LockableRandomAccessBuffer (i.e. a single
 * random access file), but with most of the metadata in memory. The data, and the larger metadata
 * such as the full keys, are read from disk when needed, and persisted to disk.
 *
 * <p>On disk format goals:
 *
 * <ol>
 *   <li>Maximise robustness.
 *   <li>Minimise seeks.
 *   <li>Minimise disk usage.
 *   <li>Be as simple as realistically possible.
 * </ol>
 *
 * <p>Overall on-disk structure: BLOCK STORAGE: Decoded data, one segment at a time (the last
 * segment's size is rounded up to a whole block). Within each segment, the number of blocks is
 * equal to the number of data blocks (plus the number of cross-check blocks if there are
 * cross-check blocks), but they are not necessarily actually data blocks (they may be check
 * blocks), and they may not be in the correct order. When we FEC decode, we read in the blocks,
 * construct the CHKs to see what keys they belong to, check that we still have enough valid keys
 * (update the metadata if the counts were wrong), do the decode, and write the data blocks back in
 * the correct order; the segment is finished. When all the segments are finished, we generate a
 * stream as usual, i.e. we still need to copy the file. It may be possible in future to simply
 * truncate the file but in many cases we need to decompress or filter, and there are significant
 * issues with code complexity and seeks during FEC decodes, see bug #6063.
 *
 * <p>KEY LIST: The original key list. Not changed when a block is fetched. - Fixed and checksummed
 * (each segment has a checksum).
 *
 * <p>SEGMENT STATUS: The status of each segment, including the status of each block, including
 * flags and where it is in the block storage within the segment. - Checksummed per segment. So it
 * needs to be written as a whole segment. Can be regenerated from the block store and key list,
 * which happens routinely when FEC decoding.
 *
 * <p>BLOOM FILTERS: Main bloom filter. Segment bloom filters.
 *
 * <p>ORIGINAL METADATA: For extra robustness, keep the full original metadata.
 *
 * <p>ORIGINAL URL: If the original key is available, keep that too.
 *
 * <p>BASIC SETTINGS: Type of splitfile, length of file, overall decryption key, number of blocks
 * and check blocks per segment, etc. - Fixed and checksummed. Read as a block so we can check the
 * checksum.
 *
 * <p>FOOTER: Length of basic settings. (So we can seek back to get them) Version number. Checksum.
 * Magic value.
 *
 * <p>OTHER NOTES:
 *
 * <p>CHECKSUMS: 4-byte CRC32.
 *
 * <p>CONCURRENCY: Callbacks into fetcher should be run off-thread, as they will usually be inside a
 * MemoryLimitedJob.
 *
 * <p>LOCKING: Trivial or taken last. Hence, can be called inside e.g. RGA calls to getCooldownTime
 * etc.
 *
 * <p>PERSISTENCE: This whole class is transient. It is recreated on startup by the
 * SplitFileFetcher. Many of the fields are also transient, e.g. SplitFileFetcherSegmentStorage's
 * cooldown fields.
 *
 * @author toad
 */
public class SplitFileFetcherStorage {
  private static final Logger LOG = LoggerFactory.getLogger(SplitFileFetcherStorage.class);

  final SplitFileFetcherStorageCallback fetcher;

  // Metadata for the fetch
  /** The underlying presumably-on-disk storage. */
  private final LockableRandomAccessBuffer raf;

  private final long rafLength;

  /**
   * If true we will complete the download by truncating the file. The file was passed in at
   * construction, and we are not responsible for freeing it. Once all segments have decoded and
   * encoded we call onSuccess(), and we don't free the data. Also, if this is true, cross-check
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
   * reconstructing missing blocks during segment decode. It remains constant for the lifetime of a
   * {@code SplitFileFetcherStorage} instance and is read-mostly; callers must treat it as
   * immutable. Implementations may allocate native buffers or other resources inside the codec, so
   * it should be reused rather than recreated for every operation.
   */
  public final FECCodec fecCodec;

  final Ticker ticker;
  final PersistentJobRunner jobRunner;
  final MemoryLimitedJobRunner memoryLimitedJobRunner;

  /**
   * Final length of the downloaded data. *BEFORE* decompression, filtering, etc. I.e. this is the
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
   * False = Transient: We are using the RAF as scratch space, we only need to write the blocks, and
   * the keys (if we don't keep them in memory). True = Persistent: It must be possible to resume
   * after a node restart. Ideally we'd like to be able to recover the download in its entirety
   * without needing any additional information, but at a minimum we want to be able to continue it
   * while passing in the usual external arguments (FetchContext, parent, etc.).
   */
  final boolean persistent;

  private boolean finishedFetcher;
  private boolean finishedEncoding;
  private boolean cancelled;
  private boolean succeeded;

  /** Errors. For now, this is not persisted. */
  private FailureCodeTracker errors;

  final int maxRetries;

  /**
   * Every cooldownTries attempts, a key will enter cooldown, and won't be re-tried for a period.
   */
  final int cooldownTries;

  /** Cooldown lasts this long for each key. */
  final long cooldownLength;

  /** Only set if all segments are in cooldown. */
  private long overallCooldownWakeupTime;

  final CompatibilityMode finalMinCompatMode;

  /** Contains Bloom filters */
  final SplitFileFetcherKeyListener keyListener;

  final RandomSource random;

  // Metadata for the file i.e. stuff we need to be able to efficiently read/write it.
  /** Offset to start of the key lists in bytes */
  final long offsetKeyList;

  /** Offset to start of the segment status'es in bytes */
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
   * client, e.g. the Identifier, whether it is on the Global queue, the client name if it isn't
   * etc.
   */
  final long offsetOriginalDetails;

  /** Offset to start of the basic settings in bytes */
  final long offsetBasicSettings;

  /** Length of all section checksums */
  final int checksumLength;

  /** Checksum implementation */
  final ChecksumChecker checksumChecker;

  private boolean hasCheckedDatastore;
  private boolean dirtyGeneralProgress;
  static final long HAS_CHECKED_DATASTORE_FLAG = 1;

  /** Fixed value posted at the end of the file (if plaintext!) */
  static final long END_MAGIC = 0x28b32d99416eb6efL;

  /** Current format version */
  static final int VERSION = 1;

  /**
   * List of segments we need to tryStartDecode() on because their metadata was corrupted on
   * startup.
   */
  private List<SplitFileFetcherSegmentStorage> segmentsToTryDecode;

  /**
   * Builder-style constructor arguments for a fresh fetch session.
   *
   * <p>This holder captures all inputs required to initialise a brand-new storage instance when a
   * splitfile fetch begins. It mirrors the metadata-driven structure of the file (segment keys,
   * compression chain, client metadata) and also includes execution-time components such as
   * schedulers, randomness and checksum policies. Instances are typically created via the nested
   * {@link InitParams.Builder} and passed to the {@link
   * SplitFileFetcherStorage#SplitFileFetcherStorage(InitParams)} constructor.
   *
   * <p>Thread-safety: {@code InitParams} is a simple data container; callers should publish it to a
   * single thread and avoid mutation once built.
   *
   * @hidden
   */
  public static final class InitParams {
    Metadata metadata;
    SplitFileFetcherStorageCallback fetcher;
    List<COMPRESSOR_TYPE> decompressors;
    ClientMetadata clientMetadata;
    boolean topDontCompress;
    short topCompatibilityMode;
    FetchContext origFetchContext;
    boolean realTime;
    KeySalter salt;
    FreenetURI thisKey;
    FreenetURI origKey;
    boolean isFinalFetch;
    byte[] clientDetails;
    RandomSource random;
    BucketFactory tempBucketFactory;
    LockableRandomAccessBufferFactory rafFactory;
    PersistentJobRunner exec;
    Ticker ticker;
    MemoryLimitedJobRunner memoryLimitedJobRunner;
    ChecksumChecker checker;
    boolean persistent;
    File storageFile;
    FileRandomAccessBufferFactory diskSpaceCheckingRAFFactory;
    KeysFetchingLocally keysFetching;

    /**
     * Fluent builder for {@link InitParams}.
     *
     * <p>The builder performs no I/O and minimal validation. Typical usage sets the metadata,
     * callback, decompression pipeline, factories, and execution helpers, then calls {@link
     * #build()} to obtain an immutable {@link InitParams} snapshot.
     *
     * <p>Unless otherwise stated, all values are required. Optional values follow sensible defaults
     * inside the storage constructor when omitted.
     */
    public static class Builder {
      private Metadata metadata;
      private SplitFileFetcherStorageCallback fetcher;
      private List<COMPRESSOR_TYPE> decompressors;
      private ClientMetadata clientMetadata;
      private boolean topDontCompress;
      private short topCompatibilityMode;
      private FetchContext origFetchContext;
      private boolean realTime;
      private KeySalter salt;
      private FreenetURI thisKey;
      private FreenetURI origKey;
      private boolean isFinalFetch;
      private byte[] clientDetails;
      private RandomSource random;
      private BucketFactory tempBucketFactory;
      private LockableRandomAccessBufferFactory rafFactory;
      private PersistentJobRunner exec;
      private Ticker ticker;
      private MemoryLimitedJobRunner memoryLimitedJobRunner;
      private ChecksumChecker checker;
      private boolean persistent;
      private File storageFile;
      private FileRandomAccessBufferFactory diskSpaceCheckingRAFFactory;
      private KeysFetchingLocally keysFetching;

      /**
       * Set the parsed splitfile {@link Metadata} required to plan the fetch.
       *
       * @param v metadata describing segments, blocks, and algorithms; must not be {@code null}.
       * @return this builder for fluent chaining.
       */
      public Builder metadata(Metadata v) {
        this.metadata = v;
        return this;
      }

      /**
       * Set the fetcher callback that receives progress and completion events.
       *
       * @param v callback implementation used for notifications; must not be {@code null}.
       * @return this builder for fluent chaining.
       */
      public Builder fetcher(SplitFileFetcherStorageCallback v) {
        this.fetcher = v;
        return this;
      }

      /**
       * Configure the decompressor pipeline to apply after block decode.
       *
       * @param v ordered list of compressor types; empty or singleton in most deployments.
       * @return this builder for fluent chaining.
       */
      public Builder decompressors(List<COMPRESSOR_TYPE> v) {
        this.decompressors = v;
        return this;
      }

      /**
       * Supply optional client metadata to attach to the completed object.
       *
       * @param v metadata such as MIME type and filename; may be {@code null}.
       * @return this builder for fluent chaining.
       */
      public Builder clientMetadata(ClientMetadata v) {
        this.clientMetadata = v;
        return this;
      }

      /**
       * Set whether the top-level container should avoid compression.
       *
       * @param v when {@code true}, skip attempting compression at the top level.
       * @return this builder for fluent chaining.
       */
      public Builder topDontCompress(boolean v) {
        this.topDontCompress = v;
        return this;
      }

      /**
       * Specify the minimum compatibility mode expected by the consumer.
       *
       * @param v numeric mode constant; affects padding and related behaviours.
       * @return this builder for fluent chaining.
       */
      public Builder topCompatibilityMode(short v) {
        this.topCompatibilityMode = v;
        return this;
      }

      /**
       * Provide the fetch context carrying retry and cooldown policy.
       *
       * @param v context with limits, timeouts, and priorities; must not be {@code null}.
       * @return this builder for fluent chaining.
       */
      public Builder fetchContext(FetchContext v) {
        this.origFetchContext = v;
        return this;
      }

      /**
       * Indicate whether the fetch should prefer reduced buffering (real-time).
       *
       * @param v when {@code true}, configure for lower latency over throughput.
       * @return this builder for fluent chaining.
       */
      public Builder realTime(boolean v) {
        this.realTime = v;
        return this;
      }

      /**
       * Set the key salter used when deriving salted keys for requests.
       *
       * @param v optional salter strategy; may be {@code null} to disable salting.
       * @return this builder for fluent chaining.
       */
      public Builder salt(KeySalter v) {
        this.salt = v;
        return this;
      }

      /**
       * Set the primary request URI associated with this fetch.
       *
       * @param v the URI for the current object; used for logging and provenance.
       * @return this builder for fluent chaining.
       */
      public Builder thisKey(FreenetURI v) {
        this.thisKey = v;
        return this;
      }

      /**
       * Optionally record the original user-facing URI if different from {@link #thisKey}.
       *
       * @param v the original or canonical URI; may be {@code null}.
       * @return this builder for fluent chaining.
       */
      public Builder origKey(FreenetURI v) {
        this.origKey = v;
        return this;
      }

      /**
       * Indicate whether this fetch corresponds to the final content rather than metadata.
       *
       * @param v set {@code true} when fetching the actual payload, not intermediate data.
       * @return this builder for fluent chaining.
       */
      public Builder isFinalFetch(boolean v) {
        this.isFinalFetch = v;
        return this;
      }

      /**
       * Attach opaque client details preserved for callbacks and auditing.
       *
       * @param v optional byte array copied/stored as provided; may be {@code null}.
       * @return this builder for fluent chaining.
       */
      public Builder clientDetails(byte[] v) {
        this.clientDetails = v;
        return this;
      }

      /**
       * Provide the source of randomness used for key scheduling and shuffling.
       *
       * @param v randomness provider; must not be {@code null} in production use.
       * @return this builder for fluent chaining.
       */
      public Builder random(RandomSource v) {
        this.random = v;
        return this;
      }

      /**
       * Set the temporary bucket factory used to stage metadata before persistence.
       *
       * @param v factory for transient buffers; required when {@code persistent} is enabled.
       * @return this builder for fluent chaining.
       */
      public Builder tempBucketFactory(BucketFactory v) {
        this.tempBucketFactory = v;
        return this;
      }

      /**
       * Configure the random-access buffer factory that creates the backing store.
       *
       * @param v factory responsible for persistent RAF creation; must be compatible with the
       *     chosen storage file.
       * @return this builder for fluent chaining.
       */
      public Builder rafFactory(LockableRandomAccessBufferFactory v) {
        this.rafFactory = v;
        return this;
      }

      /**
       * Provide the job runner used for off-thread work and callbacks.
       *
       * @param v persistent job runner implementation; must not be {@code null}.
       * @return this builder for fluent chaining.
       */
      public Builder exec(PersistentJobRunner v) {
        this.exec = v;
        return this;
      }

      /**
       * Set the time source/scheduler used for delayed tasks and de-duplication.
       *
       * @param v ticker implementation; must not be {@code null}.
       * @return this builder for fluent chaining.
       */
      public Builder ticker(Ticker v) {
        this.ticker = v;
        return this;
      }

      /**
       * Provide the memory-limited job runner used for heavy decode/encode work.
       *
       * @param v job runner aware of memory caps; must not be {@code null}.
       * @return this builder for fluent chaining.
       */
      public Builder memoryLimitedJobRunner(MemoryLimitedJobRunner v) {
        this.memoryLimitedJobRunner = v;
        return this;
      }

      /**
       * Choose the checksum implementation and length used in persisted sections.
       *
       * @param v checker implementation which also provides the checksum length.
       * @return this builder for fluent chaining.
       */
      public Builder checker(ChecksumChecker v) {
        this.checker = v;
        return this;
      }

      /**
       * Enable or disable persistence of metadata and progress across restarts.
       *
       * @param v set {@code true} to persist enough state for resumption after a restart.
       * @return this builder for fluent chaining.
       */
      public Builder persistent(boolean v) {
        this.persistent = v;
        return this;
      }

      /**
       * Provide an explicit file for the backing store when truncation is desired.
       *
       * @param v target file path; when set, completion may use truncation optimisation.
       * @return this builder for fluent chaining.
       */
      public Builder storageFile(File v) {
        this.storageFile = v;
        return this;
      }

      /**
       * Configure a disk-space checking RAF factory for safer persistent allocations.
       *
       * @param v RAF factory that validates available space; optional but recommended.
       * @return this builder for fluent chaining.
       */
      public Builder diskSpaceCheckingRAFFactory(FileRandomAccessBufferFactory v) {
        this.diskSpaceCheckingRAFFactory = v;
        return this;
      }

      /**
       * Set the key-tracking helper that marks keys as fetching locally.
       *
       * @param v helper for cross-component key accounting; may be {@code null}.
       * @return this builder for fluent chaining.
       */
      public Builder keysFetching(KeysFetchingLocally v) {
        this.keysFetching = v;
        return this;
      }

      /**
       * Build an immutable snapshot of the current builder state.
       *
       * @return a fully-populated {@link InitParams} ready for storage construction.
       */
      public InitParams build() {
        InitParams p = new InitParams();
        p.metadata = metadata;
        p.fetcher = fetcher;
        p.decompressors = decompressors;
        p.clientMetadata = clientMetadata;
        p.topDontCompress = topDontCompress;
        p.topCompatibilityMode = topCompatibilityMode;
        p.origFetchContext = origFetchContext;
        p.realTime = realTime;
        p.salt = salt;
        p.thisKey = thisKey;
        p.origKey = origKey;
        p.isFinalFetch = isFinalFetch;
        p.clientDetails = clientDetails;
        p.random = random;
        p.tempBucketFactory = tempBucketFactory;
        p.rafFactory = rafFactory;
        p.exec = exec;
        p.ticker = ticker;
        p.memoryLimitedJobRunner = memoryLimitedJobRunner;
        p.checker = checker;
        p.persistent = persistent;
        p.storageFile = storageFile;
        p.diskSpaceCheckingRAFFactory = diskSpaceCheckingRAFFactory;
        p.keysFetching = keysFetching;
        return p;
      }
    }
  }

  /**
   * Create a new storage instance backed by a fresh on-disk layout.
   *
   * <p>This constructor interprets the supplied metadata, allocates segment/cross-segment state,
   * initialises Bloom filters and checksums, and wires asynchronous helpers. It does not block on
   * network I/O but may perform bounded file I/O to prepare the persistent structures when {@code
   * persistent} is enabled in {@link InitParams}.
   *
   * <p>Callers normally place the instance under a coordinating fetcher which drives block request
   * scheduling. Once all segments finish and postconditions are met, the fetcher calls {@link
   * #streamGenerator()} to materialise the final byte stream.
   *
   * @param p full set of immutable construction parameters created by {@link InitParams.Builder};
   *     must reference the metadata for this splitfile and execution helpers such as {@code
   *     jobRunner}, {@code ticker}, and checksum policy. May not be {@code null}.
   * @throws FetchException if the fetch context indicates an unrecoverable configuration or policy
   *     error while preparing request state; this is not a network failure.
   * @throws MetadataParseException if the supplied {@link Metadata} cannot be interpreted into a
   *     valid splitfile layout (e.g., inconsistent block counts or unsupported algorithm).
   * @throws IOException if initial on-disk structures cannot be written or verified using the
   *     configured {@link LockableRandomAccessBufferFactory} and {@link BucketFactory}.
   */
  public SplitFileFetcherStorage(InitParams p)
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
        p.clientMetadata == null ? new ClientMetadata() : p.clientMetadata.clone();

    SplitFileSegmentKeys[] segmentKeys = p.metadata.getSegmentKeys();

    int crossCheckBlocks = p.metadata.getCrossCheckBlocks();

    maxRetries = p.origFetchContext.maxSplitfileBlockRetries;
    cooldownTries = p.origFetchContext.getCooldownRetries();
    cooldownLength = p.origFetchContext.getCooldownTime();
    this.splitfileSingleCryptoAlgorithm = p.metadata.getSplitfileCryptoAlgorithm();
    splitfileSingleCryptoKey = p.metadata.getSplitfileCryptoKey();

    // These are approximate values, the number of blocks per segment varies.
    int blocksPerSegment = p.metadata.getDataBlocksPerSegment();
    int checkBlocksPerSegment = p.metadata.getCheckBlocksPerSegment();

    // Accumulate sizes and counts over segments.
    AccumulatedSizes acc =
        accumulateSizes(
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
      storedBlocksLength = (long) acc.splitfileDataBlocks * CHKBlock.DATA_LENGTH;
    } else {
      storedCrossCheckBlocksLength = 0;
      storedBlocksLength =
          ((long) acc.splitfileDataBlocks + totalCrossCheckBlocks) * CHKBlock.DATA_LENGTH;
    }

    int segmentCount = p.metadata.getSegmentCount();
    validateSegmentCount(segmentCount);

    CompatibilityMode minCompatMode =
        resolveAndReportCompatibility(
            p.metadata,
            p.topDontCompress,
            p.topCompatibilityMode,
            p.origFetchContext,
            blocksPerSegment,
            checkBlocksPerSegment,
            acc.splitfileCheckBlocks);

    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Algorithm: {}, blocks per segment: {}, check blocks per segment: {}, segments: {}, data"
              + " blocks: {}, check blocks: {}",
          splitfileType,
          blocksPerSegment,
          checkBlocksPerSegment,
          segmentCount,
          acc.splitfileDataBlocks,
          acc.splitfileCheckBlocks);
    }
    segments = new SplitFileFetcherSegmentStorage[segmentCount];
    randomSegmentIterator = new RandomArrayIterator<>(segments);

    long checkLength =
        (acc.splitfileDataBlocks - (long) segmentCount * crossCheckBlocks) * CHKBlock.DATA_LENGTH;
    validateCheckLength(checkLength, finalLength);

    byte[] localSalt = new byte[32];
    random.nextBytes(localSalt);

    keyListener =
        new SplitFileFetcherKeyListener(
            fetcher,
            this,
            false,
            localSalt,
            acc.splitfileDataBlocks + totalCrossCheckBlocks + acc.splitfileCheckBlocks,
            blocksPerSegment + checkBlocksPerSegment,
            segmentCount);

    finalMinCompatMode = minCompatMode;

    this.offsetKeyList = storedBlocksLength + storedCrossCheckBlocksLength;
    this.offsetSegmentStatus = offsetKeyList + acc.storedKeysLength;

    byte[] generalProgress = encodeGeneralProgress();

    if (persistent) {
      offsetGeneralProgress = offsetSegmentStatus + acc.storedSegmentStatusLength;
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

    SegmentsBuildContext segCtx = new SegmentsBuildContext();
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
    this.crossSegments = initSegmentsAndKeys(segCtx);

    // Prepare metadata buffers and compute final layout lengths/offsets (assign finals here).
    long totalLength;
    Bucket metadataTemp;
    byte[] encodedURI;
    byte[] encodedBasicSettings;
    if (persistent) {
      PersistentPreparation prep =
          preparePersistent(
              p.metadata,
              p.tempBucketFactory,
              new OriginalDetails(p.thisKey, p.origKey, p.clientDetails, p.isFinalFetch));
      offsetOriginalDetails = prep.offsetOriginalDetails;
      this.offsetBasicSettings = prep.offsetBasicSettings;
      // Now we know encodedBasicSettings length, recompute totalLength accurately.
      metadataTemp = prep.metadataTemp;
      encodedURI = prep.encodedURI;
      // Now offsets are final, we can encode the basic settings which embed them.
      encodedBasicSettings =
          encodeBasicSettings(
              acc.splitfileDataBlocks,
              acc.splitfileCheckBlocks,
              crossCheckBlocks * segments.length);
      totalLength =
          offsetBasicSettings + encodedBasicSettings.length + 4 + checksumLength + 4 + 4 + 2 + 8;
    } else {
      totalLength = offsetSegmentStatus;
      offsetOriginalDetails = offsetBasicSettings = offsetSegmentStatus;
      metadataTemp = null;
      encodedURI = encodedBasicSettings = null;
    }

    // Create the actual LockableRandomAccessBuffer
    rafLength = totalLength;
    raf = createRAFOrThrow(p.storageFile, totalLength, p.rafFactory, p.diskSpaceCheckingRAFFactory);
    writeToRAF(
        segmentKeys, metadataTemp, encodedURI, encodedBasicSettings, totalLength, generalProgress);
    if (LOG.isDebugEnabled()) LOG.debug("Fetching {} on {} for {}", p.thisKey, this, fetcher);
    initAsyncHelpers();
  }

  /**
   * Parameters needed to resume a previously persisted fetch session.
   *
   * <p>When storage was created in persistent mode, a restart rebuilds its in-memory state by
   * reading and validating checksummed sections from the backing random access buffer. This holder
   * conveys the environment required to do so, including the buffer itself, scheduling helpers and
   * checksum implementation.
   *
   * <p>Unlike {@link InitParams}, these values are derived from the on-disk format rather than the
   * metadata that initiated the fetch. Use the nested {@link ResumeParams.Builder} to construct an
   * instance suitable for {@link SplitFileFetcherStorage#SplitFileFetcherStorage(ResumeParams)}.
   *
   * @hidden
   */
  public static final class ResumeParams {
    LockableRandomAccessBuffer raf;
    boolean realTime;
    SplitFileFetcherStorageCallback callback;
    FetchContext origContext;
    RandomSource random;
    PersistentJobRunner exec;
    KeysFetchingLocally keysFetching;
    Ticker ticker;
    MemoryLimitedJobRunner memoryLimitedJobRunner;
    ChecksumChecker checker;
    boolean newSalt;
    KeySalter salt;
    boolean resumed;
    boolean completeViaTruncation;

    /**
     * Fluent builder for {@link ResumeParams} used when reconstructing state from disk.
     *
     * <p>Callers provide the buffer to read from, runtime services (job/ticker), and flags
     * indicating whether a new salt should be injected. The resulting {@link ResumeParams} is
     * consumed by the resuming constructor.
     */
    public static class Builder {
      private LockableRandomAccessBuffer raf;
      private boolean realTime;
      private SplitFileFetcherStorageCallback callback;
      private FetchContext origContext;
      private RandomSource random;
      private PersistentJobRunner exec;
      private KeysFetchingLocally keysFetching;
      private Ticker ticker;
      private MemoryLimitedJobRunner memoryLimitedJobRunner;
      private ChecksumChecker checker;
      private boolean newSalt;
      private KeySalter salt;
      private boolean resumed;
      private boolean completeViaTruncation;

      /**
       * Set the random-access buffer to resume from.
       *
       * @param v buffer positioned at the previously persisted storage file.
       * @return this builder for fluent chaining.
       */
      public Builder raf(LockableRandomAccessBuffer v) {
        this.raf = v;
        return this;
      }

      /**
       * Configure whether resume should prefer real-time behaviour.
       *
       * @param v when {@code true}, optimises for latency over throughput.
       * @return this builder for fluent chaining.
       */
      public Builder realTime(boolean v) {
        this.realTime = v;
        return this;
      }

      /**
       * Set the callback used for notifications during the resumed session.
       *
       * @param v callback implementation; must not be {@code null}.
       * @return this builder for fluent chaining.
       */
      public Builder callback(SplitFileFetcherStorageCallback v) {
        this.callback = v;
        return this;
      }

      /**
       * Provide the original fetch context to reapply scheduling policy.
       *
       * @param v fetch context used to derive retries and cooldown; non-null.
       * @return this builder for fluent chaining.
       */
      public Builder context(FetchContext v) {
        this.origContext = v;
        return this;
      }

      /**
       * Provide the randomness source used by resumed operations.
       *
       * @param v randomness provider; must not be {@code null}.
       * @return this builder for fluent chaining.
       */
      public Builder random(RandomSource v) {
        this.random = v;
        return this;
      }

      /**
       * Set the job runner handling off-thread activity.
       *
       * @param v job runner for background tasks; must not be {@code null}.
       * @return this builder for fluent chaining.
       */
      public Builder exec(PersistentJobRunner v) {
        this.exec = v;
        return this;
      }

      /**
       * Provide the helper used to mark keys as fetching locally.
       *
       * @param v optional accounting helper.
       * @return this builder for fluent chaining.
       */
      public Builder keysFetching(KeysFetchingLocally v) {
        this.keysFetching = v;
        return this;
      }

      /**
       * Set the ticker used for timed operations and coalescing.
       *
       * @param v ticker/scheduler implementation; non-null.
       * @return this builder for fluent chaining.
       */
      public Builder ticker(Ticker v) {
        this.ticker = v;
        return this;
      }

      /**
       * Provide the memory-limited job runner for heavy tasks.
       *
       * @param v job runner respecting memory caps; must not be {@code null}.
       * @return this builder for fluent chaining.
       */
      public Builder memoryLimitedJobRunner(MemoryLimitedJobRunner v) {
        this.memoryLimitedJobRunner = v;
        return this;
      }

      /**
       * Set the checksum implementation and length for persisted sections.
       *
       * @param v checker implementation; non-null.
       * @return this builder for fluent chaining.
       */
      public Builder checker(ChecksumChecker v) {
        this.checker = v;
        return this;
      }

      /**
       * Whether to inject a new salt when resuming, if supported.
       *
       * @param v set {@code true} to prefer re-salting.
       * @return this builder for fluent chaining.
       */
      public Builder newSalt(boolean v) {
        this.newSalt = v;
        return this;
      }

      /**
       * Provide the salter to use if {@link #newSalt(boolean)} is {@code true}.
       *
       * @param v salter implementation; may be {@code null} to disable.
       * @return this builder for fluent chaining.
       */
      public Builder salt(KeySalter v) {
        this.salt = v;
        return this;
      }

      /**
       * Mark that this session represents a true resume rather than a fresh start.
       *
       * @param v set {@code true} when resuming from persisted state.
       * @return this builder for fluent chaining.
       */
      public Builder resumed(boolean v) {
        this.resumed = v;
        return this;
      }

      /**
       * Enable completion via truncation when possible.
       *
       * @param v when {@code true}, prefer truncation optimisation at completion.
       * @return this builder for fluent chaining.
       */
      public Builder completeViaTruncation(boolean v) {
        this.completeViaTruncation = v;
        return this;
      }

      /**
       * Build a {@link ResumeParams} snapshot for resuming from disk.
       *
       * @return the constructed parameters object consumed by the resuming constructor.
       */
      public ResumeParams build() {
        ResumeParams p = new ResumeParams();
        p.raf = raf;
        p.realTime = realTime;
        p.callback = callback;
        p.origContext = origContext;
        p.random = random;
        p.exec = exec;
        p.keysFetching = keysFetching;
        p.ticker = ticker;
        p.memoryLimitedJobRunner = memoryLimitedJobRunner;
        p.checker = checker;
        p.newSalt = newSalt;
        p.salt = salt;
        p.resumed = resumed;
        p.completeViaTruncation = completeViaTruncation;
        return p;
      }
    }
  }

  /**
   * Resume a persistent storage instance from an existing on-disk format.
   *
   * <p>This constructor validates footer magic, checksums, and version, locates each logical
   * section, and rebuilds segment state and Bloom filters. It also reattaches asynchronous helpers
   * and prepares any pending decode attempts when segment metadata indicates partial progress.
   *
   * @param p environment and buffer required to resume; created via {@link ResumeParams.Builder}.
   *     Must include a readable {@link LockableRandomAccessBuffer}.
   * @throws IOException if underlying storage cannot be accessed.
   * @throws StorageFormatException if the on-disk structure is corrupted or incompatible with the
   *     current format version.
   * @throws FetchException if the reconstructed state violates fetcher policy or cannot be
   *     reconciled with the provided runtime environment.
   */
  public SplitFileFetcherStorage(ResumeParams p)
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
    this.maxRetries = p.origContext.maxSplitfileBlockRetries;
    this.cooldownTries = p.origContext.getCooldownRetries();
    this.cooldownLength = p.origContext.getCooldownTime();
    // Errors are not persisted currently.
    this.errors = new FailureCodeTracker(false);
    this.completeViaTruncation = p.completeViaTruncation;

    this.rafLength = p.raf.size();
    ensureMinLength(rafLength);
    validateMagic(rafLength);
    byte[] versionBuf = readVersionBytes(rafLength);
    int version = parseInt(versionBuf);
    if (version != VERSION) throw new StorageFormatException("Wrong version " + version);
    byte[] checksumTypeBuf = readChecksumTypeBytes(rafLength);
    validateChecksumType(checksumTypeBuf);
    byte[] flagsBuf = readFlagsBytes(rafLength);
    validateFlags(flagsBuf);

    BasicSettingsInfo basicInfo =
        readBasicSettingsLocation(rafLength, flagsBuf, checksumTypeBuf, versionBuf);
    byte[] basicSettingsBuffer = readChecksummed(basicInfo.offset, basicInfo.length);

    ParsedBasicSettings parsed =
        parseBasicSettings(basicSettingsBuffer, basicInfo.offset, p.completeViaTruncation);

    // Assign parsed values to final fields
    this.splitfileType = parsed.splitfileType;
    this.fecCodec = FECCodec.getInstance(splitfileType);
    this.splitfileSingleCryptoAlgorithm = parsed.splitfileSingleCryptoAlgorithm;
    this.splitfileSingleCryptoKey = parsed.splitfileSingleCryptoKey;
    this.finalLength = parsed.finalLength;
    this.decompressedLength = parsed.decompressedLength;
    this.clientMetadata = parsed.clientMetadata;
    this.decompressors = parsed.decompressors;
    this.offsetKeyList = parsed.offsetKeyList;
    this.offsetSegmentStatus = parsed.offsetSegmentStatus;
    this.offsetGeneralProgress = parsed.offsetGeneralProgress;
    this.offsetMainBloomFilter = parsed.offsetMainBloomFilter;
    this.offsetSegmentBloomFilters = parsed.offsetSegmentBloomFilters;
    this.offsetOriginalMetadata = parsed.offsetOriginalMetadata;
    this.offsetOriginalDetails = parsed.offsetOriginalDetails;
    this.offsetBasicSettings = parsed.offsetBasicSettings;
    this.finalMinCompatMode = parsed.finalMinCompatMode;

    // Allocate and assign segments array before constructing individual segments.
    this.segments = new SplitFileFetcherSegmentStorage[parsed.segmentCount];
    this.randomSegmentIterator = new RandomArrayIterator<>(segments);
    SegmentsInit segmentsInit =
        initSegmentsFromStream(
            parsed.totalDataBlocks,
            parsed.totalCheckBlocks,
            parsed.totalCrossCheckBlocks,
            parsed.settingsStream,
            p.completeViaTruncation,
            p.keysFetching,
            this.segments);
    this.crossSegments = segmentsInit.crossSegments;
    this.keyListener =
        new SplitFileFetcherKeyListener(
            this, fetcher, segmentsInit.remainingStream, false, p.newSalt);

    postInitReadSegmentState();
    readGeneralProgress();
    initAsyncHelpers();
  }

  // ---------- Small helpers to reduce cognitive complexity in constructor ----------

  private void ensureMinLength(long length) throws StorageFormatException {
    if (length < 8) throw new StorageFormatException("Too short");
  }

  private void validateMagic(long length) throws IOException, StorageFormatException {
    byte[] buf = new byte[8];
    raf.pread(length - 8, buf, 0, 8);
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(buf));
    if (dis.readLong() != END_MAGIC) throw new StorageFormatException("Wrong magic bytes");
  }

  private static int parseInt(byte[] buf) throws IOException {
    return new DataInputStream(new ByteArrayInputStream(buf)).readInt();
  }

  private byte[] readVersionBytes(long length) throws IOException {
    byte[] versionBuf = new byte[4];
    raf.pread(length - 12, versionBuf, 0, 4);
    return versionBuf;
  }

  private byte[] readChecksumTypeBytes(long length) throws IOException {
    byte[] checksumTypeBuf = new byte[2];
    raf.pread(length - 14, checksumTypeBuf, 0, 2);
    return checksumTypeBuf;
  }

  private void validateChecksumType(byte[] checksumTypeBuf)
      throws IOException, StorageFormatException {
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(checksumTypeBuf));
    int checksumType = dis.readShort();
    if (checksumType != ChecksumChecker.CHECKSUM_CRC)
      throw new StorageFormatException("Unknown checksum type " + checksumType);
  }

  private byte[] readFlagsBytes(long length) throws IOException {
    byte[] flagsBuf = new byte[4];
    raf.pread(length - 18, flagsBuf, 0, 4);
    return flagsBuf;
  }

  private void validateFlags(byte[] flagsBuf) throws IOException, StorageFormatException {
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(flagsBuf));
    int flags = dis.readInt();
    if (flags != 0) throw new StorageFormatException("Unknown flags: " + flags);
  }

  private BasicSettingsInfo readBasicSettingsLocation(
      long length, byte[] flagsBuf, byte[] checksumTypeBuf, byte[] versionBuf)
      throws IOException, StorageFormatException {
    byte[] buf = new byte[14];
    raf.pread(length - (22 + checksumLength), buf, 0, 4);
    byte[] checksum = new byte[checksumLength];
    raf.pread(length - (18 + checksumLength), checksum, 0, checksumLength);
    System.arraycopy(flagsBuf, 0, buf, 4, 4);
    System.arraycopy(checksumTypeBuf, 0, buf, 8, 2);
    System.arraycopy(versionBuf, 0, buf, 10, 4);
    if (!checksumChecker.checkChecksum(buf, 0, 14, checksum))
      throw new StorageFormatException("Checksum failed on basic settings length and version");
    int basicSettingsLength = parseInt(buf);
    if (basicSettingsLength < 0
        || basicSettingsLength + 12 + 4 + checksumLength > raf.size()
        || basicSettingsLength > 1024 * 1024)
      throw new StorageFormatException("Bad basic settings length");
    long basicSettingsOffset = length - (18 + 4 + checksumLength * 2L + basicSettingsLength);
    return new BasicSettingsInfo(basicSettingsOffset, basicSettingsLength);
  }

  private byte[] readChecksummed(long offset, int length)
      throws StorageFormatException, IOException {
    byte[] basicSettingsBuffer = new byte[length];
    try {
      preadChecksummed(offset, basicSettingsBuffer, 0, length);
    } catch (ChecksumFailedException e) {
      throw new StorageFormatException("Basic settings checksum invalid");
    }
    return basicSettingsBuffer;
  }

  private ParsedBasicSettings parseBasicSettings(
      byte[] basicSettingsBuffer, long basicSettingsOffset, boolean completeViaTruncation)
      throws StorageFormatException {
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(basicSettingsBuffer));
    try {
      SplitfileAlgorithm splitfileAlgorithm = readSplitfileAlgorithm(dis);
      CryptoInfo crypto = readCryptoInfo(dis, splitfileAlgorithm);
      LengthsInfo lengths = readLengths(dis);
      HeaderInfo header = new HeaderInfo(splitfileAlgorithm, crypto, lengths);
      ClientMetadata cm = readClientMetadataSafe(dis);
      List<COMPRESSOR_TYPE> decomps = readDecompressors(dis);
      OffsetsInfo offsets = readOffsets(dis, basicSettingsOffset, completeViaTruncation);
      CompatAndCounts compat = readCompatAndCounts(dis);
      return new ParsedBasicSettings(header, cm, decomps, offsets, compat, dis);
    } catch (IOException e) {
      throw new StorageFormatException(
          "Cannot read basic settings even though passed checksum: " + e, e);
    }
  }

  private SplitfileAlgorithm readSplitfileAlgorithm(DataInputStream dis)
      throws IOException, StorageFormatException {
    short s = dis.readShort();
    try {
      return SplitfileAlgorithm.getByCode(s);
    } catch (IllegalArgumentException e) {
      throw new StorageFormatException("Invalid splitfile type " + s);
    }
  }

  private static class CryptoInfo {
    final byte algorithm;
    final byte[] key;

    CryptoInfo(byte algorithm, byte[] key) {
      this.algorithm = algorithm;
      this.key = key;
    }
  }

  private CryptoInfo readCryptoInfo(DataInputStream dis, SplitfileAlgorithm splitfileAlgorithm)
      throws IOException, StorageFormatException {
    byte alg = dis.readByte();
    if (!Metadata.isValidSplitfileCryptoAlgorithm(alg))
      throw new StorageFormatException("Invalid splitfile crypto algorithm " + splitfileAlgorithm);
    byte[] key = null;
    if (dis.readBoolean()) {
      key = new byte[32];
      dis.readFully(key);
    }
    return new CryptoInfo(alg, key);
  }

  private static class LengthsInfo {
    final long finalLength;
    final long decompressedLength;

    LengthsInfo(long finalLength, long decompressedLength) {
      this.finalLength = finalLength;
      this.decompressedLength = decompressedLength;
    }
  }

  private static class HeaderInfo {
    final SplitfileAlgorithm splitfileType;
    final CryptoInfo crypto;
    final LengthsInfo lengths;

    HeaderInfo(SplitfileAlgorithm splitfileType, CryptoInfo crypto, LengthsInfo lengths) {
      this.splitfileType = splitfileType;
      this.crypto = crypto;
      this.lengths = lengths;
    }
  }

  private LengthsInfo readLengths(DataInputStream dis) throws IOException, StorageFormatException {
    long finalLen = dis.readLong();
    if (finalLen < 0) throw new StorageFormatException("Invalid final length " + finalLen);
    long decompLen = dis.readLong();
    if (decompLen < 0) throw new StorageFormatException("Invalid decompressed length " + decompLen);
    return new LengthsInfo(finalLen, decompLen);
  }

  private ClientMetadata readClientMetadataSafe(DataInputStream dis)
      throws IOException, StorageFormatException {
    try {
      return ClientMetadata.construct(dis);
    } catch (MetadataParseException e) {
      throw new StorageFormatException("Invalid MIME type");
    }
  }

  private List<COMPRESSOR_TYPE> readDecompressors(DataInputStream dis)
      throws IOException, StorageFormatException {
    int decompressorCount = dis.readInt();
    if (decompressorCount < 0)
      throw new StorageFormatException("Invalid decompressor count " + decompressorCount);
    List<COMPRESSOR_TYPE> decomps = new ArrayList<>(decompressorCount);
    for (int i = 0; i < decompressorCount; i++) {
      short type = dis.readShort();
      COMPRESSOR_TYPE d = COMPRESSOR_TYPE.getCompressorByMetadataID(type);
      if (d == null) throw new StorageFormatException("Invalid decompressor ID " + type);
      decomps.add(d);
    }
    return decomps;
  }

  private static class OffsetsInfo {
    final long offsetKeyList;
    final long offsetSegmentStatus;
    final long offsetGeneralProgress;
    final long offsetMainBloomFilter;
    final long offsetSegmentBloomFilters;
    final long offsetOriginalMetadata;
    final long offsetOriginalDetails;
    final long offsetBasicSettings;

    OffsetsInfo(long... offsets) {
      this.offsetKeyList = offsets[0];
      this.offsetSegmentStatus = offsets[1];
      this.offsetGeneralProgress = offsets[2];
      this.offsetMainBloomFilter = offsets[3];
      this.offsetSegmentBloomFilters = offsets[4];
      this.offsetOriginalMetadata = offsets[5];
      this.offsetOriginalDetails = offsets[6];
      this.offsetBasicSettings = offsets[7];
    }
  }

  private OffsetsInfo readOffsets(
      DataInputStream dis, long basicSettingsOffset, boolean completeViaTruncation)
      throws IOException, StorageFormatException {
    long keyListOff = readValidatedOffset(dis, "key list");
    long segmentStatusOff = readValidatedOffset(dis, "segment status");
    long generalProgressOff = readValidatedOffset(dis, "general progress");
    long mainBloomOff = readValidatedOffset(dis, "main bloom filter");
    long segmentBloomOff = readValidatedOffset(dis, "segment bloom filters");
    long origMetaOff = readValidatedOffset(dis, "original metadata");
    long origDetailsOff = readValidatedOffset(dis, "original metadata");
    long basicSettingsOff = dis.readLong();
    if (basicSettingsOff != basicSettingsOffset)
      throw new StorageFormatException("Invalid basic settings offset (not the same as computed)");
    if (completeViaTruncation != dis.readBoolean())
      throw new StorageFormatException("Complete via truncation flag is wrong");
    return new OffsetsInfo(
        keyListOff,
        segmentStatusOff,
        generalProgressOff,
        mainBloomOff,
        segmentBloomOff,
        origMetaOff,
        origDetailsOff,
        basicSettingsOff);
  }

  private long readValidatedOffset(DataInputStream dis, String what)
      throws IOException, StorageFormatException {
    long value = dis.readLong();
    if (value < 0 || value > rafLength)
      throw new StorageFormatException("Invalid offset (" + what + ")");
    return value;
  }

  private static class CompatAndCounts {
    final CompatibilityMode mode;
    final int segmentCount;
    final int totalDataBlocks;
    final int totalCheckBlocks;
    final int totalCrossCheckBlocks;

    CompatAndCounts(
        CompatibilityMode mode,
        int segmentCount,
        int totalDataBlocks,
        int totalCheckBlocks,
        int totalCrossCheckBlocks) {
      this.mode = mode;
      this.segmentCount = segmentCount;
      this.totalDataBlocks = totalDataBlocks;
      this.totalCheckBlocks = totalCheckBlocks;
      this.totalCrossCheckBlocks = totalCrossCheckBlocks;
    }
  }

  private CompatAndCounts readCompatAndCounts(DataInputStream dis)
      throws IOException, StorageFormatException {
    int compatMode = dis.readInt();
    if (compatMode < 0 || compatMode > CompatibilityMode.values().length)
      throw new StorageFormatException("Invalid compatibility mode " + compatMode);
    CompatibilityMode finalMode = CompatibilityMode.values()[compatMode];
    int segmentCount = dis.readInt();
    if (segmentCount <= 0)
      throw new StorageFormatException("Invalid segment count " + segmentCount);
    int totalDataBlocks = dis.readInt();
    if (totalDataBlocks < 0)
      throw new StorageFormatException("Invalid total data blocks " + totalDataBlocks);
    int totalCheckBlocks = dis.readInt();
    if (totalCheckBlocks < 0)
      throw new StorageFormatException("Invalid total check blocks " + totalDataBlocks);
    int totalCrossCheckBlocks = dis.readInt();
    if (totalCrossCheckBlocks < 0)
      throw new StorageFormatException("Invalid total cross-check blocks " + totalDataBlocks);
    if (totalDataBlocks + totalCheckBlocks + totalCrossCheckBlocks <= 0) {
      throw new StorageFormatException("Total number of blocks in splitfile is non-positive");
    }
    return new CompatAndCounts(
        finalMode, segmentCount, totalDataBlocks, totalCheckBlocks, totalCrossCheckBlocks);
  }

  private SegmentsInit initSegmentsFromStream(
      int totalDataBlocks,
      int totalCheckBlocks,
      int totalCrossCheckBlocks,
      DataInputStream dis,
      boolean completeViaTruncation,
      KeysFetchingLocally keysFetching,
      SplitFileFetcherSegmentStorage[] segments)
      throws StorageFormatException, IOException {
    // segments array is provided and already assigned to this.segments
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
      lp.parent = this;
      lp.dis = dis;
      lp.segNo = i;
      lp.writeRetries = maxRetries != -1;
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
              splitfileSingleCryptoKey != null,
              checksumLength);
      segmentStatusOffset +=
          SplitFileFetcherSegmentStorage.paddedStoredSegmentStatusLength(
              dataBlocks, checkBlocks, crossCheckBlocks, maxRetries != -1, checksumLength, true);
      validateSegmentOffsets(dataOffset, segments[i]);
      debugSegmentOffsets(i, segments[i]);
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
      crossSegmentsLocal[i] = new SplitFileFetcherCrossSegmentStorage(this, i, dis);
    }
    return new SegmentsInit(segments, crossSegmentsLocal, dis);
  }

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

  private void debugSegmentOffsets(int index, SplitFileFetcherSegmentStorage segment) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Segment {}: data blocks offset {} cross-check blocks offset {} for segment {} of {}",
          index,
          segment.segmentBlockDataOffset,
          segment.segmentCrossCheckBlockDataOffset,
          index,
          this);
    }
  }

  private void validateSegmentOffsets(long dataOffset, SplitFileFetcherSegmentStorage segment)
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

  private void postInitReadSegmentState()
      throws FetchException, IOException, StorageFormatException {
    for (SplitFileFetcherSegmentStorage segment : segments) {
      boolean needsDecode = determineIfSegmentNeedsDecode(segment);
      if (needsDecode) queueSegmentForDecode(segment);
    }
    readAllSegmentKeys();
    checkCrossSegmentsIfAny();
  }

  private boolean determineIfSegmentNeedsDecode(SplitFileFetcherSegmentStorage segment)
      throws FetchException, IOException, StorageFormatException {
    boolean needsDecode = false;
    try {
      segment.readMetadata();
      if (segment.hasFailed()) {
        raf.close();
        raf.free(); // Failed, so free it.
        throw new FetchException(FetchExceptionMode.SPLITFILE_ERROR, errors);
      }
    } catch (ChecksumFailedException e) {
      LOG.error("Progress for segment {} on {} corrupted.", segment.segNo, this);
      needsDecode = true;
    }
    if (segment.needsDecode()) needsDecode = true;
    return needsDecode;
  }

  private void queueSegmentForDecode(SplitFileFetcherSegmentStorage segment) {
    if (segmentsToTryDecode == null) segmentsToTryDecode = new ArrayList<>();
    segmentsToTryDecode.add(segment);
  }

  private void readAllSegmentKeys() throws StorageFormatException, IOException {
    for (SplitFileFetcherSegmentStorage segment : segments) {
      try {
        segment.readSegmentKeys();
      } catch (ChecksumFailedException e) {
        throw new StorageFormatException("Keys corrupted");
      }
    }
  }

  private void checkCrossSegmentsIfAny() {
    if (this.crossSegments == null) return;
    for (SplitFileFetcherCrossSegmentStorage crossSegment : this.crossSegments)
      // Must be after reading the metadata for the plain segments.
      crossSegment.checkBlocks();
  }

  private static class BasicSettingsInfo {
    final long offset;
    final int length;

    BasicSettingsInfo(long offset, int length) {
      this.offset = offset;
      this.length = length;
    }
  }

  private static class ParsedBasicSettings {
    final SplitfileAlgorithm splitfileType;
    final byte splitfileSingleCryptoAlgorithm;
    final byte[] splitfileSingleCryptoKey;
    final long finalLength;
    final long decompressedLength;
    final ClientMetadata clientMetadata;
    final List<COMPRESSOR_TYPE> decompressors;
    final long offsetKeyList;
    final long offsetSegmentStatus;
    final long offsetGeneralProgress;
    final long offsetMainBloomFilter;
    final long offsetSegmentBloomFilters;
    final long offsetOriginalMetadata;
    final long offsetOriginalDetails;
    final long offsetBasicSettings;
    final CompatibilityMode finalMinCompatMode;
    final int segmentCount;
    final int totalDataBlocks;
    final int totalCheckBlocks;
    final int totalCrossCheckBlocks;
    final DataInputStream settingsStream;

    ParsedBasicSettings(
        HeaderInfo header,
        ClientMetadata clientMetadata,
        List<COMPRESSOR_TYPE> decompressors,
        OffsetsInfo offsets,
        CompatAndCounts compat,
        DataInputStream settingsStream) {
      this.splitfileType = header.splitfileType;
      this.splitfileSingleCryptoAlgorithm = header.crypto.algorithm;
      this.splitfileSingleCryptoKey = header.crypto.key;
      this.finalLength = header.lengths.finalLength;
      this.decompressedLength = header.lengths.decompressedLength;
      this.clientMetadata = clientMetadata;
      this.decompressors = decompressors;
      this.offsetKeyList = offsets.offsetKeyList;
      this.offsetSegmentStatus = offsets.offsetSegmentStatus;
      this.offsetGeneralProgress = offsets.offsetGeneralProgress;
      this.offsetMainBloomFilter = offsets.offsetMainBloomFilter;
      this.offsetSegmentBloomFilters = offsets.offsetSegmentBloomFilters;
      this.offsetOriginalMetadata = offsets.offsetOriginalMetadata;
      this.offsetOriginalDetails = offsets.offsetOriginalDetails;
      this.offsetBasicSettings = offsets.offsetBasicSettings;
      this.finalMinCompatMode = compat.mode;
      this.segmentCount = compat.segmentCount;
      this.totalDataBlocks = compat.totalDataBlocks;
      this.totalCheckBlocks = compat.totalCheckBlocks;
      this.totalCrossCheckBlocks = compat.totalCrossCheckBlocks;
      this.settingsStream = settingsStream;
    }
  }

  private static class SegmentsInit {
    final SplitFileFetcherSegmentStorage[] segments;
    final SplitFileFetcherCrossSegmentStorage[] crossSegments;
    final DataInputStream remainingStream;

    SegmentsInit(
        SplitFileFetcherSegmentStorage[] segments,
        SplitFileFetcherCrossSegmentStorage[] crossSegments,
        DataInputStream remainingStream) {
      this.segments = segments;
      this.crossSegments = crossSegments;
      this.remainingStream = remainingStream;
    }
  }

  private void readGeneralProgress() throws IOException {
    try {
      byte[] buf = preadChecksummedWithLength(offsetGeneralProgress);
      ByteArrayInputStream bais = new ByteArrayInputStream(buf);
      DataInputStream dis = new DataInputStream(bais);
      long flags = dis.readLong();
      if ((flags & HAS_CHECKED_DATASTORE_FLAG) != 0) hasCheckedDatastore = true;
      errors = new FailureCodeTracker(false, dis);
      dis.close();
    } catch (ChecksumFailedException | StorageFormatException e) {
      LOG.error("Failed to read general progress: {}", String.valueOf(e));
      // Reset general progress
      this.hasCheckedDatastore = false;
      this.errors = new FailureCodeTracker(false);
    }
  }

  private byte[] encodeGeneralProgress() {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try {
      OutputStream ccos = checksumChecker.checksumWriterWithLength(baos, new ArrayBucketFactory());
      DataOutputStream dos = new DataOutputStream(ccos);
      long flags = 0;
      if (hasCheckedDatastore) flags |= HAS_CHECKED_DATASTORE_FLAG;
      dos.writeLong(flags);
      errors.writeFixedLengthTo(dos);
      dos.close();
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return baos.toByteArray();
  }

  /**
   * Start the storage layer.
   *
   * @param resume True only if we are restarting without having serialized, i.e. from the file
   *     only. In this case we will need to tell the parent how many blocks have been fetched.
   * @return True if it should be scheduled immediately. If false, the storage layer will call back
   *     into the fetcher later.
   */
  public boolean start(boolean resume) {
    if (resume) onResumeInit();
    restartCrossSegments();
    scheduleTryDecodeForBrokenSegments();
    if (keyListener.needsKeys()) return regenerateKeysAsync();
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

  private void restartCrossSegments() {
    if (crossSegments == null) return;
    for (SplitFileFetcherCrossSegmentStorage segment : crossSegments) {
      segment.restart();
    }
  }

  private void scheduleTryDecodeForBrokenSegments() {
    if (segmentsToTryDecode == null) return;
    List<SplitFileFetcherSegmentStorage> brokenSegments;
    synchronized (SplitFileFetcherStorage.this) {
      brokenSegments = segmentsToTryDecode;
      segmentsToTryDecode = null;
    }
    if (brokenSegments == null) return;
    for (SplitFileFetcherSegmentStorage segment : brokenSegments) {
      segment.tryStartDecode();
    }
  }

  private boolean regenerateKeysAsync() {
    try {
      this.jobRunner.queue(
          context -> {
            regenerateKeysJob();
            return false;
          },
          NativeThread.PriorityLevel.LOW_PRIORITY.value + 1);
    } catch (PersistenceDisabledException e) {
      // Ignore.
    }
    return false;
  }

  private void regenerateKeysJob() {
    // Regenerating filters for this storage
    LOG.error("Regenerating filters for {}", SplitFileFetcherStorage.this);
    KeySalter salt = fetcher.getSalter();
    if (!addAllKeysFromSegments(salt)) return;
    keyListener.addedAllKeys();
    writeBloomFiltersSafely();
    fetcher.restartedAfterDataCorruption();
    LOG.warn("Finished regenerating filters for {}", SplitFileFetcherStorage.this);
  }

  private boolean addAllKeysFromSegments(KeySalter salt) {
    for (int i = 0; i < segments.length; i++) {
      SplitFileFetcherSegmentStorage segment = segments[i];
      try {
        SplitFileSegmentKeys keys = segment.readSegmentKeys();
        for (int j = 0; j < keys.totalKeys(); j++) {
          keyListener.addKey(keys.getKey(j, null, false).getNodeKey(false), i, salt);
        }
      } catch (IOException | ChecksumFailedException e) {
        if (e instanceof IOException io) {
          failOnDiskError(io);
        } else {
          failOnDiskError((ChecksumFailedException) e);
        }
        return false;
      }
    }
    return true;
  }

  private void writeBloomFiltersSafely() {
    try {
      keyListener.initialWriteSegmentBloomFilters(offsetSegmentBloomFilters);
      keyListener.innerWriteMainBloomFilter(offsetMainBloomFilter);
    } catch (IOException e) {
      if (persistent) failOnDiskError(e);
    }
  }

  OutputStream checksumOutputStream(OutputStream os) {
    return checksumChecker.checksumWriter(os);
  }

  private byte[] encodeBasicSettings(
      int totalDataBlocks, int totalCheckBlocks, int totalCrossCheckBlocks) {
    return appendChecksum(
        innerEncodeBasicSettings(totalDataBlocks, totalCheckBlocks, totalCrossCheckBlocks));
  }

  /** Encode the basic settings (number of blocks etc.) to a byte array */
  private byte[] innerEncodeBasicSettings(
      int totalDataBlocks, int totalCheckBlocks, int totalCrossCheckBlocks) {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    try {
      dos.writeShort(splitfileType.code);
      dos.writeByte(this.splitfileSingleCryptoAlgorithm);
      dos.writeBoolean(this.splitfileSingleCryptoKey != null);
      if (this.splitfileSingleCryptoKey != null) {
        assert (splitfileSingleCryptoKey.length == 32);
        dos.write(splitfileSingleCryptoKey);
      }
      dos.writeLong(this.finalLength);
      dos.writeLong(this.decompressedLength);
      clientMetadata.writeTo(dos);
      // Record number of decompressors; any size constraints are enforced upstream.
      dos.writeInt(decompressors.size());
      for (COMPRESSOR_TYPE c : decompressors) dos.writeShort(c.metadataID);
      dos.writeLong(offsetKeyList);
      dos.writeLong(offsetSegmentStatus);
      dos.writeLong(offsetGeneralProgress);
      dos.writeLong(offsetMainBloomFilter);
      dos.writeLong(offsetSegmentBloomFilters);
      dos.writeLong(offsetOriginalMetadata);
      dos.writeLong(offsetOriginalDetails);
      dos.writeLong(offsetBasicSettings);
      dos.writeBoolean(completeViaTruncation);
      dos.writeInt(finalMinCompatMode.ordinal());
      dos.writeInt(segments.length);
      dos.writeInt(totalDataBlocks);
      dos.writeInt(totalCheckBlocks);
      dos.writeInt(totalCrossCheckBlocks);
      for (SplitFileFetcherSegmentStorage segment : segments) {
        segment.writeFixedMetadata(dos);
      }
      if (this.crossSegments == null) dos.writeInt(0);
      else {
        dos.writeInt(crossSegments.length);
        for (SplitFileFetcherCrossSegmentStorage segment : crossSegments) {
          segment.writeFixedMetadata(dos);
        }
      }
      keyListener.writeStaticSettings(dos);
    } catch (IOException e) {
      throw new IllegalStateException(e); // Unexpected for in-memory buffer
    }
    return baos.toByteArray();
  }

  /**
   * Write details needed to restart the download from scratch, and to identify whether it is useful
   * to do so.
   */
  private byte[] encodeAndChecksumOriginalDetails(
      FreenetURI thisKey, FreenetURI origKey, byte[] clientDetails, boolean isFinalFetch)
      throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    dos.writeUTF(thisKey.toASCIIString());
    dos.writeUTF(origKey.toASCIIString());
    dos.writeBoolean(isFinalFetch);
    dos.writeInt(clientDetails.length);
    dos.write(clientDetails);
    dos.writeInt(maxRetries);
    dos.writeInt(cooldownTries);
    dos.writeLong(cooldownLength);
    return checksumChecker.appendChecksum(baos.toByteArray());
  }

  /** Container for accumulated sizing information computed from segment keys and configuration. */
  private static final class AccumulatedSizes {
    final int splitfileDataBlocks;
    final int splitfileCheckBlocks;
    final long storedKeysLength;
    final long storedSegmentStatusLength;

    AccumulatedSizes(
        int splitfileDataBlocks,
        int splitfileCheckBlocks,
        long storedKeysLength,
        long storedSegmentStatusLength) {
      this.splitfileDataBlocks = splitfileDataBlocks;
      this.splitfileCheckBlocks = splitfileCheckBlocks;
      this.storedKeysLength = storedKeysLength;
      this.storedSegmentStatusLength = storedSegmentStatusLength;
    }
  }

  /** Bundles details needed to initialize persistent metadata sections. */
  private static final class OriginalDetails {
    final FreenetURI thisKey;
    final FreenetURI origKey;
    final byte[] clientDetails;
    final boolean isFinalFetch;

    OriginalDetails(
        FreenetURI thisKey, FreenetURI origKey, byte[] clientDetails, boolean isFinalFetch) {
      this.thisKey = thisKey;
      this.origKey = origKey;
      this.clientDetails = clientDetails;
      this.isFinalFetch = isFinalFetch;
    }
  }

  /** Context needed to build segments and keys while computing offsets. */
  private static final class SegmentsBuildContext {
    Metadata metadata;
    SplitFileSegmentKeys[] segmentKeys;
    int crossCheckBlocks;
    int blocksPerSegment;
    int checkBlocksPerSegment;
    FetchContext origFetchContext;
    KeySalter salt;
    KeysFetchingLocally keysFetching;
    AccumulatedSizes acc;
    long storedBlocksLength;
    long storedCrossCheckBlocksLength;
  }

  private static AccumulatedSizes accumulateSizes(
      SplitFileSegmentKeys[] segmentKeys,
      int crossCheckBlocks,
      boolean hasSplitfileSingleCryptoKey,
      int checksumLength,
      int maxRetries,
      boolean persistent) {
    int splitfileDataBlocks = 0;
    int splitfileCheckBlocks = 0;
    long storedKeysLength = 0;
    long storedSegmentStatusLength = 0;
    for (SplitFileSegmentKeys keys : segmentKeys) {
      int dataBlocks = keys.getDataBlocks();
      int checkBlocks = keys.getCheckBlocks();
      splitfileDataBlocks += dataBlocks;
      splitfileCheckBlocks += checkBlocks;
      storedKeysLength +=
          SplitFileFetcherSegmentStorage.storedKeysLength(
              dataBlocks, checkBlocks, hasSplitfileSingleCryptoKey, checksumLength);
      storedSegmentStatusLength +=
          SplitFileFetcherSegmentStorage.paddedStoredSegmentStatusLength(
              dataBlocks - crossCheckBlocks,
              checkBlocks,
              crossCheckBlocks,
              maxRetries != -1,
              checksumLength,
              persistent);
    }
    // Subtract cross-check blocks from data blocks to get the actual data blocks.
    splitfileDataBlocks -= segmentKeys.length * crossCheckBlocks;
    return new AccumulatedSizes(
        splitfileDataBlocks, splitfileCheckBlocks, storedKeysLength, storedSegmentStatusLength);
  }

  private static final class PersistentPreparation {
    final Bucket metadataTemp;
    final byte[] encodedURI;
    final long totalLength;
    final long offsetOriginalDetails;
    final long offsetBasicSettings;

    PersistentPreparation(
        Bucket metadataTemp,
        byte[] encodedURI,
        long totalLength,
        long offsetOriginalDetails,
        long offsetBasicSettings) {
      this.metadataTemp = metadataTemp;
      this.encodedURI = encodedURI;
      this.totalLength = totalLength;
      this.offsetOriginalDetails = offsetOriginalDetails;
      this.offsetBasicSettings = offsetBasicSettings;
    }
  }

  private PersistentPreparation preparePersistent(
      Metadata metadata, BucketFactory tempBucketFactory, OriginalDetails details)
      throws FetchException, IOException {
    Bucket metadataTemp = tempBucketFactory.makeBucket(-1);
    try (OutputStream os = metadataTemp.getOutputStream();
        OutputStream cos = checksumOutputStream(os);
        BufferedOutputStream bos = new BufferedOutputStream(cos)) {
      MultiHashOutputStream mos = new MultiHashOutputStream(bos, HashType.SHA256.bitmask);
      metadata.writeTo(new DataOutputStream(mos));
      mos.getResults()[0].writeTo(bos);
    } catch (MetadataUnresolvedException e) {
      throw new FetchException(
          FetchExceptionMode.INTERNAL_ERROR,
          "Metadata not resolved starting splitfile fetch?!: " + e,
          e);
    }
    long metadataLength = metadataTemp.size();
    long computedOffsetOriginalDetails = offsetOriginalMetadata + metadataLength;

    byte[] encodedURI =
        encodeAndChecksumOriginalDetails(
            details.thisKey, details.origKey, details.clientDetails, details.isFinalFetch);
    long computedOffsetBasicSettings = computedOffsetOriginalDetails + encodedURI.length;

    //noinspection PointlessArithmeticExpression
    long totalLength =
        computedOffsetBasicSettings /* offset of basic settings */
            + 0 /* encodedBasicSettings length (computed after assigning offsets) */
            + 4 /* basic settings length */
            + checksumLength /* footer checksum */
            + 4 /* version */
            + 4 /* flags */
            + 2 /* checksum type */
            + 8 /* magic */;

    return new PersistentPreparation(
        metadataTemp,
        encodedURI,
        totalLength,
        computedOffsetOriginalDetails,
        computedOffsetBasicSettings);
  }

  private void writeToRAF(
      SplitFileSegmentKeys[] segmentKeys,
      Bucket metadataTemp,
      byte[] encodedURI,
      byte[] encodedBasicSettings,
      long totalLength,
      byte[] generalProgress)
      throws IOException {
    try (AutoCloseableRafLock ignored = autoLockOpen()) {
      for (int i = 0; i < segments.length; i++) {
        SplitFileFetcherSegmentStorage segment = segments[i];
        segment.writeKeysWithChecksum(segmentKeys[i]);
      }
      if (persistent) {
        for (SplitFileFetcherSegmentStorage segment : segments) segment.writeMetadata();
        raf.pwrite(offsetGeneralProgress, generalProgress, 0, generalProgress.length);
        keyListener.innerWriteMainBloomFilter(offsetMainBloomFilter);
        keyListener.initialWriteSegmentBloomFilters(offsetSegmentBloomFilters);
        BucketTools.copyTo(metadataTemp, raf, offsetOriginalMetadata, -1);
        metadataTemp.free();
        raf.pwrite(offsetOriginalDetails, encodedURI, 0, encodedURI.length);
        raf.pwrite(offsetBasicSettings, encodedBasicSettings, 0, encodedBasicSettings.length);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(encodedBasicSettings.length - checksumLength);
        byte[] bufToWrite = baos.toByteArray();
        baos = new ByteArrayOutputStream();
        dos = new DataOutputStream(baos);
        dos.writeInt(0);
        dos.writeShort(checksumChecker.getChecksumTypeID());
        dos.writeInt(VERSION);
        byte[] version = baos.toByteArray();
        byte[] bufToChecksum = Arrays.copyOf(bufToWrite, bufToWrite.length + version.length);
        System.arraycopy(version, 0, bufToChecksum, bufToWrite.length, version.length);
        byte[] checksum = checksumChecker.generateChecksum(bufToChecksum);
        raf.pwrite(
            offsetBasicSettings + encodedBasicSettings.length, bufToWrite, 0, bufToWrite.length);
        raf.pwrite(
            offsetBasicSettings + encodedBasicSettings.length + bufToWrite.length,
            checksum,
            0,
            checksum.length);
        raf.pwrite(
            offsetBasicSettings + encodedBasicSettings.length + bufToWrite.length + checksum.length,
            version,
            0,
            version.length);
        baos = new ByteArrayOutputStream();
        dos = new DataOutputStream(baos);
        dos.writeLong(END_MAGIC);
        byte[] buf = baos.toByteArray();
        raf.pwrite(totalLength - 8, buf, 0, 8);
      }
    }
  }

  private AutoCloseableRafLock autoLockOpen() throws IOException {
    return new AutoCloseableRafLock(raf.lockOpen());
  }

  private static final class AutoCloseableRafLock implements AutoCloseable {
    private final RAFLock lock;

    AutoCloseableRafLock(RAFLock lock) {
      this.lock = lock;
    }

    @Override
    public void close() {
      lock.unlock();
    }
  }

  private static void validateCheckLength(long checkLength, long finalLength)
      throws FetchException {
    if (checkLength > finalLength && checkLength - finalLength > CHKBlock.DATA_LENGTH)
      throw new FetchException(
          FetchExceptionMode.INVALID_METADATA,
          "Splitfile is " + checkLength + " bytes long but length is " + finalLength + " bytes");
  }

  private LockableRandomAccessBuffer createRAFOrThrow(
      File storageFile,
      long totalLength,
      LockableRandomAccessBufferFactory rafFactory,
      FileRandomAccessBufferFactory diskSpaceCheckingRAFFactory)
      throws IOException {
    if (storageFile != null) {
      if (!storageFile.exists()) throw new IOException("Must have already created storage file");
      if (storageFile.length() > 0) throw new IOException("Storage file must be empty");
      LOG.info("Creating splitfile storage file for complete-via-truncation: {}", storageFile);
      return diskSpaceCheckingRAFFactory.createNewRAF(storageFile, totalLength, random);
    } else {
      return rafFactory.makeRAF(totalLength);
    }
  }

  private static void validateSegmentCount(int segmentCount) {
    if (segmentCount <= 0) {
      throw new AssertionError("A splitfile has to have at least one segment");
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
              || !(minCompatMode.ordinal() > topCompatibilityMode
                  || maxCompatMode.ordinal() < topCompatibilityMode)) {
            minCompatMode = maxCompatMode = CompatibilityMode.values()[topCompatibilityMode];
            dontCompress = topDontCompress;
          } else {
            throw new FetchException(
                FetchExceptionMode.INVALID_METADATA,
                "Top compatibility mode is incompatible with detected compatibility mode");
          }
        }
        fetcher.onSplitfileCompatibilityMode(
            minCompatMode,
            maxCompatMode,
            metadata.getCustomSplitfileKey(),
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
    if ((blocksPerSegment > origFetchContext.maxDataBlocksPerSegment)
        || (checkBlocksPerSegment > origFetchContext.maxCheckBlocksPerSegment)) {
      throw new FetchException(
          FetchExceptionMode.TOO_MANY_BLOCKS_PER_SEGMENT,
          "Too many blocks per segment: "
              + blocksPerSegment
              + " data, "
              + checkBlocksPerSegment
              + " check");
    }
  }

  private SplitFileFetcherCrossSegmentStorage[] initSegmentsAndKeys(SegmentsBuildContext ctx)
      throws FetchException {
    long dataOffset = 0;
    long crossCheckBlocksOffset = ctx.storedBlocksLength; // Only used if completeViaTruncation
    long segmentKeysOffset = offsetKeyList;
    long segmentStatusOffset = offsetSegmentStatus;

    for (int i = 0; i < segments.length; i++) {
      SplitFileSegmentKeys keys = ctx.segmentKeys[i];
      final int dataBlocks = keys.getDataBlocks() - ctx.crossCheckBlocks;
      final int checkBlocks = keys.getCheckBlocks();
      validateBlocksPerSegmentLimit(ctx.origFetchContext, dataBlocks, checkBlocks);
      SplitFileFetcherSegmentStorage.InitParams p = new SplitFileFetcherSegmentStorage.InitParams();
      p.parent = this;
      p.segNumber = i;
      p.dataBlocks = dataBlocks;
      p.checkBlocks = checkBlocks;
      p.crossCheckBlocks = ctx.crossCheckBlocks;
      p.segmentDataOffset = dataOffset;
      p.segmentCrossCheckDataOffset = completeViaTruncation ? crossCheckBlocksOffset : -1;
      p.segmentKeysOffset = segmentKeysOffset;
      p.segmentStatusOffset = segmentStatusOffset;
      p.writeRetries = maxRetries != -1;
      p.keys = keys;
      p.keysFetching = ctx.keysFetching;
      segments[i] = new SplitFileFetcherSegmentStorage(p);
      dataOffset += (long) dataBlocks * CHKBlock.DATA_LENGTH;
      if (!completeViaTruncation) {
        dataOffset += (long) ctx.crossCheckBlocks * CHKBlock.DATA_LENGTH;
      } else {
        crossCheckBlocksOffset += (long) ctx.crossCheckBlocks * CHKBlock.DATA_LENGTH;
      }
      segmentKeysOffset +=
          SplitFileFetcherSegmentStorage.storedKeysLength(
              dataBlocks + ctx.crossCheckBlocks,
              checkBlocks,
              splitfileSingleCryptoKey != null,
              checksumLength);
      segmentStatusOffset +=
          SplitFileFetcherSegmentStorage.paddedStoredSegmentStatusLength(
              dataBlocks,
              checkBlocks,
              ctx.crossCheckBlocks,
              maxRetries != -1,
              checksumLength,
              persistent);
      for (int j = 0; j < (dataBlocks + ctx.crossCheckBlocks + checkBlocks); j++) {
        keyListener.addKey(keys.getKey(j, null, false).getNodeKey(false), i, ctx.salt);
      }
      debugSegmentOffsets(i, segments[i]);
    }
    assert (dataOffset == ctx.storedBlocksLength);
    assert !completeViaTruncation
        || (crossCheckBlocksOffset == ctx.storedCrossCheckBlocksLength + ctx.storedBlocksLength);
    assert (segmentKeysOffset
        == ctx.storedBlocksLength + ctx.storedCrossCheckBlocksLength + ctx.acc.storedKeysLength);
    assert (segmentStatusOffset
        == ctx.storedBlocksLength
            + ctx.storedCrossCheckBlocksLength
            + ctx.acc.storedKeysLength
            + ctx.acc.storedSegmentStatusLength);

    // Lie about the required number of blocks. See original inline comment for rationale.
    int totalCrossCheckBlocks = ctx.segmentKeys.length * ctx.crossCheckBlocks;
    fetcher.setSplitfileBlocks(
        ctx.acc.splitfileDataBlocks + totalCrossCheckBlocks, ctx.acc.splitfileCheckBlocks);

    keyListener.finishedSetup();

    return createCrossSegments(ctx.metadata, ctx.crossCheckBlocks, ctx.blocksPerSegment);
  }

  private SplitFileFetcherCrossSegmentStorage[] createCrossSegments(
      Metadata metadata, int crossCheckBlocks, int blocksPerSegment) {
    SplitFileFetcherCrossSegmentStorage[] xSegments;
    if (crossCheckBlocks == 0) return new SplitFileFetcherCrossSegmentStorage[0];
    Random crossSegmentRandom =
        MersenneTwister.createUnsynchronized(
            Metadata.getCrossSegmentSeed(metadata.getHashes(), metadata.getHashThisLayerOnly()));
    xSegments = new SplitFileFetcherCrossSegmentStorage[segments.length];
    int segLen = blocksPerSegment;
    int deductBlocksFromSegments = metadata.getDeductBlocksFromSegments();
    for (int i = 0; i < xSegments.length; i++) {
      LOG.info("Allocating blocks (on fetch) for cross segment {}", i);
      if (segments.length - i == deductBlocksFromSegments) {
        segLen--;
      }
      SplitFileFetcherCrossSegmentStorage seg =
          new SplitFileFetcherCrossSegmentStorage(i, segLen, crossCheckBlocks, this, fecCodec);
      xSegments[i] = seg;
      for (int j = 0; j < segLen; j++) {
        allocateCrossDataBlock(seg, crossSegmentRandom);
      }
      for (int j = 0; j < crossCheckBlocks; j++) {
        allocateCrossCheckBlock(seg, crossSegmentRandom);
      }
    }
    return xSegments;
  }

  /** Reserved for future use. */
  private void allocateCrossDataBlock(SplitFileFetcherCrossSegmentStorage segment, Random random) {
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
  private void allocateCrossCheckBlock(SplitFileFetcherCrossSegmentStorage segment, Random random) {
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

  /**
   * Priority class forwarded to the request scheduler.
   *
   * <p>The class originates from the owning fetcher and influences how aggressively requests are
   * scheduled relative to other work.
   *
   * @return the priority class value defined by the fetcher.
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
   * post-processing is done.
   *
   * @param segment the segment instance that has just reported success; must be one of {@link
   *     #segments} and non-null. The parameter is used for logging and does not change behaviour.
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
        context -> {
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
   * Create a {@link StreamGenerator} that materialises the final decoded data stream.
   *
   * <p>The returned generator emits the data blocks for all segments in logical order and applies
   * any required transformations (e.g., decompression) declared by the metadata. The generator
   * performs blocking file reads; callers should invoke it off the request-selection thread.
   *
   * <pre>{@code
   * // Example: write the reconstructed bytes to an OutputStream
   * var gen = storage.streamGenerator();
   * gen.writeTo(outputStream, clientContext);
   * }</pre>
   *
   * @return a generator that reads from the underlying storage and writes the complete payload on
   *     demand. The instance is stateless between invocations of {@code writeTo} and not thread
   *     safe.
   */
  public StreamGenerator streamGenerator() {
    // Truncation optimisation can be added in future if safe.
    return new StreamGenerator() {

      @Override
      public void writeTo(OutputStream os, ClientContext context) throws IOException {
        try (AutoCloseableRafLock ignored = autoLockOpen()) {
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

  static final long LAZY_WRITE_METADATA_DELAY = TimeUnit.MINUTES.toMillis(5);

  private PersistentJob writeMetadataJob;

  private void writeGeneralProgressInner() {
    synchronized (this) {
      if (!dirtyGeneralProgress) return;
      dirtyGeneralProgress = false;
    }
    byte[] generalProgress = encodeGeneralProgress();
    try {
      raf.pwrite(offsetGeneralProgress, generalProgress, 0, generalProgress.length);
    } catch (IOException e) {
      failOnDiskError(e);
    }
  }

  private void initAsyncHelpers() {
    this.writeMetadataJob =
        context -> {
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
   * Schedule a best-effort metadata write.
   *
   * <p>When running in persistent mode, metadata changes are checkpointed asynchronously to reduce
   * contention and I/O overhead. Calls may coalesce when invoked in quick succession. In
   * non-persistent mode this method is a no-op.
   */
  public void lazyWriteMetadata() {
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
   * Mark the associated fetcher as finished and trigger resource cleanup when eligible.
   *
   * <p>When both the fetcher and the encoder have finished (and truncation is not pending), the
   * storage closes its backing file off-thread. Repeated calls are safe and ignored after the first
   * transition.
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
        context -> {
          // ATOMICITY/DURABILITY: This will run after the checkpoint after completion.
          // So after restart, even if the checkpoint failed, we will be in a valid state.
          // This is why this is queue() not queueInternal().
          close();
          return true;
        });
  }

  private void finishedEncoding() {
    FinishState state = computeFinishEncodingState();
    if (state.alreadyFinished) return;
    if (state.lateCompletion) {
      if (allFinished() && !allSucceeded()) {
        fail(new FetchException(FetchExceptionMode.SPLITFILE_ERROR, errors));
      } else {
        if (completeViaTruncation) raf.close();
        maybeComplete();
        return;
      }
    }
    if (state.waitingForFetcher) return;
    closeOffThread();
  }

  private static final class FinishState {
    final boolean alreadyFinished;
    final boolean lateCompletion;
    final boolean waitingForFetcher;

    FinishState(boolean alreadyFinished, boolean lateCompletion, boolean waitingForFetcher) {
      this.alreadyFinished = alreadyFinished;
      this.lateCompletion = lateCompletion;
      this.waitingForFetcher = waitingForFetcher;
    }
  }

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
   * not guaranteed to have encoded all blocks etc. But we still need the callback in case e.g. we
   * are in the process of failing, and can't proceed until all the encode jobs have finished.
   */
  void finishedEncoding(SplitFileFetcherSegmentStorage segment) {
    if (LOG.isDebugEnabled())
      LOG.debug("Successfully decoded {} for {} for {}", segment, this, fetcher);
    if (!allFinished()) return;
    finishedEncoding();
  }

  /**
   * Called when a cross-segment has finished decoding. It doesn't necessarily have a "finished"
   * state, except if it was cancelled.
   */
  void finishedEncoding(SplitFileFetcherCrossSegmentStorage segment) {
    if (LOG.isDebugEnabled())
      LOG.debug("Successfully decoded {} for {} for {}", segment, this, fetcher);
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
   * inspect error codes and progress.
   *
   * @param e the failure cause describing mode and context; must not be {@code null}. The instance
   *     is forwarded to the fetcher's {@code fail} callback without modification.
   */
  public void fail(final FetchException e) {
    if (LOG.isDebugEnabled()) LOG.debug("Failing {} with error {} and codes {}", this, e, errors);
    jobRunner.queueNormalOrDrop(
        context -> {
          fetcher.fail(e);
          return true;
        });
  }

  /**
   * Abort the splitfile when a segment exhausts its retry budget.
   *
   * <p>This helper converts the condition into a consolidated {@link FetchException} and routes it
   * through {@link #fail(FetchException)} so shutdown happens consistently.
   *
   * @param segment the segment that can no longer make progress; used for logging only.
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
   * notification occurs off-thread to avoid blocking callers inside I/O paths.
   *
   * @param e the I/O exception observed while reading or writing persistent state.
   */
  public void failOnDiskError(final IOException e) {
    LOG.error("Failing on disk error: {}", e, e);
    jobRunner.queueNormalOrDrop(
        context -> {
          fetcher.failOnDiskError(e);
          return true;
        });
  }

  /**
   * Report a checksum verification failure to the fetcher.
   *
   * <p>The storage zeroes the affected bytes and surfaces the failure via the callback. Depending
   * on policy, the fetcher may propagate the error or attempt recovery using redundant blocks.
   *
   * @param e the checksum failure raised when verifying a checksummed section from disk.
   */
  public void failOnDiskError(final ChecksumFailedException e) {
    LOG.error("Failing on unrecoverable corrupt data: {}", e, e);
    jobRunner.queueNormalOrDrop(
        context -> {
          fetcher.failOnDiskError(e);
          return true;
        });
  }

  /**
   * Count the number of not-yet-fetched keys across all segments.
   *
   * <p>The value includes keys that are currently cooling down or temporarily skipped. It is
   * computed from in-memory segment state and does not perform disk I/O.
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
   * <p>The result depends on the current time, retry counters and segment-level cooldown. It is
   * intended for request schedulers to estimate near-term concurrency.
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
   * outcomes with storage state. Equality and hash semantics consider both the segment number and
   * intra-segment block number.
   */
  public final class SplitFileFetcherStorageKey
      implements SendableRequestItem, SendableRequestItemKey {

    /**
     * Create a key handle for the given block and segment.
     *
     * @param n zero-based block number within the segment; values outside the segment's range are
     *     invalid and must not be supplied.
     * @param segNo zero-based segment index inside the enclosing storage.
     * @param storage the owning storage, used for lookups and logging; must not be {@code null}.
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
     * <p>Intended for diagnostics and test support; output format is not part of the public API.
     */
    @Override
    public void dump() {
      // Ignore.
    }

    /**
     * Convert this handle into a request-layer key.
     *
     * @return an immutable {@link SendableRequestItemKey} suitable for use by request senders.
     */
    @Override
    public SendableRequestItemKey getKey() {
      return this;
    }

    /**
     * Value equality based on segment and block indices.
     *
     * @param o another object; equality holds when it is also a {@code SplitFileFetcherStorageKey}
     *     with identical segment and block numbers.
     * @return {@code true} when the two keys identify the same block, otherwise {@code false}.
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
     * @return a stable hash suitable for use in hash-based collections.
     */
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
     * @return a concise string containing the segment and block numbers.
     */
    public String toString() {
      return "SplitFileFetcherStorageKey:" + segmentNumber + ":" + blockNumber;
    }
  }

  /**
   * Choose a random eligible key from non-decoding, non-finished segments.
   *
   * <p>The selection uses a time‑varying seed to distribute requests and avoids segments currently
   * decoding or ineligible due to cooldown/retry constraints. Returns {@code null} when no key is
   * presently sendable.
   *
   * @return a randomly selected {@link SplitFileFetcherStorageKey} or {@code null} if none is
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

  /** Cancel the download, stop all FEC decodes, and call close() off-thread when done. */
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
   * <p>When a check produces a definitive result the storage updates segment state and may schedule
   * additional work. The method runs off-thread to avoid blocking request selection.
   *
   * @param context execution context associated with the check; may carry throttling or logging
   *     configuration.
   */
  public void finishedCheckingDatastoreOnLocalRequest(ClientContext context) {
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
   * <p>The error is accumulated in the failure tracker and the key is made retryable according to
   * the configured policy. Persistent sessions schedule a metadata checkpoint.
   *
   * @param key the key whose request failed; used to locate the segment and block counters.
   * @param fe the reason for failure, including {@link FetchExceptionMode} and context.
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
   * <p>On I/O failure the storage reports a disk error and returns {@code null}.
   *
   * @param key a handle returned by {@link #chooseRandomKey()} or constructed by a caller.
   * @return the corresponding {@link ClientKey} when available; otherwise {@code null} on storage
   *     failure.
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
   * @return a non‑negative limit; when reached a segment failure is raised and the splitfile fails.
   */
  public int maxRetries() {
    return maxRetries;
  }

  /**
   * Notify the fetcher that a block has permanently failed.
   *
   * <p>The notification is posted asynchronously. It does not modify storage state directly.
   */
  public void failedBlock() {
    jobRunner.queueNormalOrDrop(
        context -> {
          fetcher.onFailedBlock();
          return false;
        });
  }

  /**
   * Indicate whether the final block may omit padding due to compatibility mode.
   *
   * @return {@code true} when padding is not guaranteed for the last block, otherwise {@code
   *     false}.
   */
  public boolean lastBlockMightNotBePadded() {
    return (finalMinCompatMode == CompatibilityMode.COMPAT_UNKNOWN
        || finalMinCompatMode.ordinal() < CompatibilityMode.COMPAT_1416.ordinal());
  }

  /**
   * Called after a corruption recovery path has restarted the session.
   *
   * <p>Clears cooldown if appropriate and relays a notification to the fetcher on a background
   * thread.
   */
  public void restartedAfterDataCorruption() {
    jobRunner.queueNormalOrDrop(
        context -> {
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
        context -> {
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
   * <p>This is safe to call frequently; it performs cheap checks and posts to the fetcher when the
   * global flag changes.
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
   * there is no pending cooldown or a future epoch millisecond timestamp to wait until.
   *
   * @param now the current epoch time in milliseconds used to clamp stale values.
   * @return {@code -1} if finished, {@code 0} if no cooldown, or a future epoch millisecond
   *     timestamp.
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

  /** Append a CRC32 to a (short) byte[] */
  private byte[] appendChecksum(byte[] data) {
    return checksumChecker.appendChecksum(data);
  }

  void preadChecksummed(long fileOffset, byte[] buf, int offset, int length)
      throws IOException, ChecksumFailedException {
    byte[] checksumBuf = new byte[checksumLength];
    try (AutoCloseableRafLock ignored = autoLockOpen()) {
      raf.pread(fileOffset, buf, offset, length);
      raf.pread(fileOffset + length, checksumBuf, 0, checksumLength);
    }
    if (!checksumChecker.checkChecksum(buf, offset, length, checksumBuf)) {
      Arrays.fill(buf, offset, offset + length, (byte) 0);
      throw new ChecksumFailedException();
    }
  }

  byte[] preadChecksummedWithLength(long fileOffset)
      throws IOException, ChecksumFailedException, StorageFormatException {
    byte[] checksumBuf = new byte[checksumLength];
    byte[] lengthBuf = new byte[8];
    byte[] buf;
    int length;
    try (AutoCloseableRafLock ignored = autoLockOpen()) {
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
      Arrays.fill(buf, 0, length, (byte) 0);
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
   * @param context the execution context present when the check completed.
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
   * @return {@code true} once the first check has completed, otherwise {@code false}.
   */
  public synchronized boolean hasCheckedStore() {
    return hasCheckedDatastore;
  }

  void onShutdown(ClientContext context) {
    writeMetadataJob.run(context);
  }
}

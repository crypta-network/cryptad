package network.crypta.client.async;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.crypt.SHA256;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeCHK;
import network.crypta.node.SendableGet;
import network.crypta.support.BinaryBloomFilter;
import network.crypta.support.BloomFilter;
import network.crypta.support.CountingBloomFilter;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * KeyListener implementation that uses layered Bloom filters to decide whether a fetched key is
 * relevant to an in‑progress splitfile download.
 *
 * <p>This listener maintains two tiers of probabilistic membership structures: a global counting
 * Bloom filter that tracks all outstanding keys for the whole fetch, and a fixed array of
 * per‑segment Bloom filters that narrow the decision to a specific segment. Callers first consult
 * {@link #probablyWantKey(Key, byte[])} with the globally salted routing key. If the main filter
 * matches, a local salt is applied and the per‑segment filters are checked. A positive match from
 * both tiers allows the caller to escalate to {@link #definitelyWantKey(Key, byte[],
 * ClientContext)} and eventually {@link #handleBlock(Key, byte[], KeyBlock, ClientContext)}.
 *
 * <p>When configured as {@linkplain #persistent() persistent}, the listener serializes its Bloom
 * filters to disk so long‑running fetches can resume without recomputing filter contents. The main
 * filter is mutable and written lazily as keys are consumed; per‑segment filters are immutable once
 * built and are written once. The class is thread‑aware: short hot‑path methods avoid blocking and
 * use minimal synchronized sections. Internal buffers are heap‑backed and do not require explicit
 * closing.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> fast screening of keys, segment localization, and
 *       removal of consumed keys from the main filter.
 *   <li><strong>Notable behavior:</strong> two independent salts are used—one global (provided by
 *       the caller as {@code saltedKey}) and one local (applied here) to reduce cross‑talk between
 *       tiers.
 *   <li><strong>Concurrency:</strong> mutation of filters is guarded; read checks favor low
 *       contention and avoid I/O.
 * </ul>
 *
 * @see SplitFileFetcherStorage
 * @see SplitFileFetcherStorageCallback
 * @see BinaryBloomFilter
 * @see CountingBloomFilter
 * @see KeyListener
 * @see NodeCHK
 * @see CHKBlock
 */
public class SplitFileFetcherKeyListener implements KeyListener {
  private static final Logger LOG = LoggerFactory.getLogger(SplitFileFetcherKeyListener.class);

  /**
   * Upper bound for the serialized main Bloom filter size in bytes.
   *
   * <p>This mirrors the maximum size implied by the constructor path where the number of Bloom
   * filter bits is capped to {@link Integer#MAX_VALUE} and then converted to a counting Bloom
   * filter (bytes = bits/8 * 2).
   */
  private static final int MAX_MAIN_BLOOM_FILTER_SIZE_BYTES =
      (int) (((Integer.MAX_VALUE + 7L) & ~7L) / 8L * 2L);

  final SplitFileFetcherStorage storage;
  final SplitFileFetcherStorageCallback fetcher;

  /**
   * Salt used in the secondary Bloom filters if the primary matches. The primary Bloom filters use
   * the already-salted saltedKey.
   */
  private final byte[] localSalt;

  /** Size of the main Bloom filter in bytes. */
  private final int mainBloomFilterSizeBytes;

  /**
   * Default mainBloomElementsPerKey. False positives are approx 0.6185^[this number], so 19 gives
   * us 0.01% false positives, which should be acceptable even if there are thousands of splitfiles
   * on the queue.
   */
  static final int DEFAULT_MAIN_BLOOM_ELEMENTS_PER_KEY = 19;

  /** Number of hashes for the main filter. */
  private final int mainBloomK;

  /**
   * What proportion of false positives is acceptable for the per-segment Bloom filters? This is
   * divided by the number of segments, so it is (roughly) an overall probability of any false
   * positive given that we reach the per-segment filters. IMHO 1 in 100 is adequate.
   */
  static final double ACCEPTABLE_BLOOM_FALSE_POSITIVES_ALL_SEGMENTS = 0.01;

  /**
   * Size of a per-segment bloom filter in bytes. This is calculated from the above constant and the
   * number of segments and rounded up.
   */
  private final int perSegmentBloomFilterSizeBytes;

  /** Number of hashes for the per-segment bloom filters. */
  private final int perSegmentK;

  /**
   * The overall bloom filter, containing all the keys, salted with the global hash. When a key is
   * found, it is removed from this.
   */
  private final CountingBloomFilter filter;

  /** The per-segment bloom filters, containing the keys for each segment. These are not changed. */
  private final BinaryBloomFilter[] segmentFilters;

  private volatile boolean finishedSetup;
  private final boolean persistent;

  /** Does the main bloom filter need writing? */
  private boolean dirty;

  private volatile boolean mustRegenerateMainFilter;
  private volatile boolean mustRegenerateSegmentFilters;

  // No dedicated close lifecycle: filters are heap-backed here and do not
  // require explicit closing; cleanup is deferred to GC.

  /**
   * Create a listener and initialize in‑memory Bloom filters for a new splitfile download.
   *
   * <p>This constructor builds the global counting Bloom filter and one immutable per‑segment Bloom
   * filter for each segment. Sizes are derived from the total number of blocks and segments to
   * achieve a small, bounded false‑positive rate. No disk I/O occurs here; callers may persist the
   * filters later via {@link #innerWriteMainBloomFilter(long)} and {@link
   * #initialWriteSegmentBloomFilters(long)} when appropriate.
   *
   * @param fetcher callback that provides priority and failure handling; never {@code null}; used
   *     to propagate disk errors and get the request priority class
   * @param storage backing storage that exposes segment metadata and persistence helpers; must
   *     correspond to the same splitfile layout and segment count supplied below
   * @param persistent whether this listener participates in persistence and triggers lazy metadata
   *     writes after key removals; {@code true} enables on‑disk snapshots
   * @param localSalt 32‑byte salt applied locally before querying per‑segment filters; the array is
   *     read only by the listener and not modified
   * @param origSize total number of blocks across all segments; must be positive and reflect the
   *     original splitfile size as scheduled by the fetcher
   * @param segBlocks number of blocks per segment used to size per‑segment filters; must be
   *     positive and will be capped at {@code origSize}
   * @param segments number of segments in the splitfile; must be positive and match {@code
   *     storage.segments.length}
   * @throws FetchException when any of the numeric arguments are non‑positive or imply a Bloom
   *     filter larger than the supported bounds for this implementation
   */
  public SplitFileFetcherKeyListener(
      SplitFileFetcherStorageCallback fetcher,
      SplitFileFetcherStorage storage,
      boolean persistent,
      byte[] localSalt,
      int origSize,
      int segBlocks,
      int segments)
      throws FetchException {
    if (origSize <= 0) {
      throw new FetchException(
          FetchExceptionMode.INTERNAL_ERROR,
          "Cannot listen for non-positive number of blocks: " + origSize);
    }
    if (segBlocks <= 0) {
      throw new FetchException(
          FetchExceptionMode.INTERNAL_ERROR,
          "Cannot listen for non-positive number of blocks per segment: " + segBlocks);
    }
    if (segments <= 0) {
      throw new FetchException(
          FetchExceptionMode.INTERNAL_ERROR,
          "Cannot listen for non-positive number of segments: " + segments);
    }
    this.fetcher = fetcher;
    this.storage = storage;
    this.localSalt = localSalt;
    this.persistent = persistent;
    int mainElementsPerKey = DEFAULT_MAIN_BLOOM_ELEMENTS_PER_KEY;
    mainBloomK = (int) (mainElementsPerKey * 0.7);
    long elementsLong = (long) origSize * mainElementsPerKey;
    // REDFLAG: SIZE LIMIT: 3.36TB limit!
    if (elementsLong > Integer.MAX_VALUE)
      throw new FetchException(
          FetchExceptionMode.TOO_BIG,
          "Cannot fetch splitfiles with more than "
              + (Integer.MAX_VALUE / mainElementsPerKey)
              + " keys! (approx 3.3TB)");
    int mainSizeBits = (int) elementsLong; // counting filter
    mainSizeBits = (mainSizeBits + 7) & ~7; // round up to bytes
    mainBloomFilterSizeBytes = mainSizeBits / 8 * 2; // counting filter
    double acceptableFalsePositives = ACCEPTABLE_BLOOM_FALSE_POSITIVES_ALL_SEGMENTS / segments;
    int perSegmentBitsPerKey =
        (int) Math.ceil(Math.log(acceptableFalsePositives) / Math.log(0.6185));
    if (segBlocks > origSize) segBlocks = origSize;
    int perSegmentSize = perSegmentBitsPerKey * segBlocks;
    perSegmentSize = (perSegmentSize + 7) & ~7;
    perSegmentBloomFilterSizeBytes = perSegmentSize / 8;
    perSegmentK = BloomFilter.optimalK(perSegmentSize, segBlocks);
    segmentFilters = new BinaryBloomFilter[segments];
    byte[] segmentsFilterBuffer = new byte[perSegmentBloomFilterSizeBytes * segments];
    ByteBuffer baseBuffer = ByteBuffer.wrap(segmentsFilterBuffer);
    int start = 0;
    int end = perSegmentBloomFilterSizeBytes;
    for (int i = 0; i < segments; i++) {
      baseBuffer.position(start);
      baseBuffer.limit(end);
      ByteBuffer slice;

      slice = baseBuffer.slice();
      //noinspection resource
      segmentFilters[i] =
          new BinaryBloomFilter(slice, perSegmentBloomFilterSizeBytes * 8, perSegmentK);
      start += perSegmentBloomFilterSizeBytes;
      end += perSegmentBloomFilterSizeBytes;
    }
    byte[] filterBuffer = new byte[mainBloomFilterSizeBytes];
    filter = new CountingBloomFilter(mainBloomFilterSizeBytes * 8 / 2, mainBloomK, filterBuffer);
    filter.setWarnOnRemoveFromEmpty();
  }

  /**
   * Reconstruct a listener and its Bloom filter state from persisted metadata.
   *
   * <p>This constructor restores the fixed per‑segment Bloom filters from the storage file and, if
   * the salt has not changed, attempts to restore the mutable main counting Bloom filter as well. A
   * failed checksum for either region marks the corresponding structure for regeneration; callers
   * should subsequently feed all keys back through {@link #addKey(Key, int, KeySalter)} and call
   * {@link #addedAllKeys()} once complete. This method triggers no network activity.
   *
   * @param storage backing storage that provides offsets and lengths for the persisted filter
   *     regions; must expose a consistent {@code segments} array for sizing
   * @param callback fetcher callback that supplies priority and failure reporting; must not be
   *     {@code null}
   * @param dis input stream positioned at the beginning of this listener's static settings; the
   *     method reads {@code localSalt}, sizes, and hash counts in the order written by {@link
   *     #writeStaticSettings(DataOutputStream)}
   * @param persistent whether this instance will perform lazy metadata writes when keys are
   *     removed; set according to the parent fetch configuration
   * @param newSalt when {@code true}, the main Bloom filter is not read from disk because the salt
   *     differs; the filter will be regenerated from keys instead
   * @throws IOException if the input stream cannot be read fully for settings or filter regions
   * @throws StorageFormatException when the persisted sizes or parameters are invalid or when
   *     checksum verification fails for a region that must be readable
   */
  public SplitFileFetcherKeyListener(
      SplitFileFetcherStorage storage,
      SplitFileFetcherStorageCallback callback,
      DataInputStream dis,
      boolean persistent,
      boolean newSalt)
      throws IOException, StorageFormatException {
    this.storage = storage;
    this.fetcher = callback;
    this.persistent = persistent;
    localSalt = new byte[32];
    dis.readFully(localSalt);
    mainBloomFilterSizeBytes = dis.readInt();
    if (mainBloomFilterSizeBytes < 0
        || mainBloomFilterSizeBytes > MAX_MAIN_BLOOM_FILTER_SIZE_BYTES) {
      throw new StorageFormatException("Bad main bloom filter size");
    }
    mainBloomK = dis.readInt();
    if (mainBloomK < 1) throw new StorageFormatException("Bad main bloom filter K");
    perSegmentBloomFilterSizeBytes = dis.readInt();
    if (perSegmentBloomFilterSizeBytes < 0)
      throw new StorageFormatException("Bad per segment bloom filter size");
    perSegmentK = dis.readInt();
    if (perSegmentK < 0) throw new StorageFormatException("Bad per segment bloom filter K");
    int segments = storage.segments.length;
    segmentFilters = new BinaryBloomFilter[segments];
    byte[] segmentsFilterBuffer = new byte[perSegmentBloomFilterSizeBytes * segments];
    try {
      storage.preadChecksummed(
          storage.offsetSegmentBloomFilters, segmentsFilterBuffer, 0, segmentsFilterBuffer.length);
    } catch (ChecksumFailedException e) {
      LOG.error(
          "Check-summed read for segment filters at {} failed for {}",
          storage.offsetSegmentBloomFilters,
          this,
          e);
      mustRegenerateSegmentFilters = true;
    }
    ByteBuffer baseBuffer = ByteBuffer.wrap(segmentsFilterBuffer);
    int start = 0;
    int end = perSegmentBloomFilterSizeBytes;
    for (int i = 0; i < segments; i++) {
      baseBuffer.position(start);
      baseBuffer.limit(end);
      ByteBuffer slice;

      slice = baseBuffer.slice();
      //noinspection resource
      segmentFilters[i] =
          new BinaryBloomFilter(slice, perSegmentBloomFilterSizeBytes * 8, perSegmentK);
      start += perSegmentBloomFilterSizeBytes;
      end += perSegmentBloomFilterSizeBytes;
    }
    byte[] filterBuffer = new byte[mainBloomFilterSizeBytes];
    if (!newSalt) {
      try {
        storage.preadChecksummed(
            storage.offsetMainBloomFilter, filterBuffer, 0, mainBloomFilterSizeBytes);
      } catch (ChecksumFailedException e) {
        LOG.error(
            "Check-summed read for main filters at {} failed for {}",
            storage.offsetMainBloomFilter,
            this,
            e);
        mustRegenerateMainFilter = true;
      }
    } else {
      mustRegenerateMainFilter = true;
    }
    filter = new CountingBloomFilter(mainBloomFilterSizeBytes * 8 / 2, mainBloomK, filterBuffer);
    filter.setWarnOnRemoveFromEmpty();
  }

  /** SplitFileFetcher adds keys in whatever blocks are convenient. */
  synchronized void addKey(Key key, int segNo, KeySalter salter) {
    if (finishedSetup && !(mustRegenerateMainFilter || mustRegenerateSegmentFilters))
      throw new IllegalStateException();
    if (mustRegenerateMainFilter || !finishedSetup) {
      byte[] saltedKey = salter.saltKey(key);
      filter.addKey(saltedKey);
    }
    if (mustRegenerateSegmentFilters || !finishedSetup) {
      byte[] localSalted = localSaltKey(key);
      segmentFilters[segNo].addKey(localSalted);
    }
  }

  synchronized void finishedSetup() {
    finishedSetup = true;
  }

  private byte[] localSaltKey(Key key) {
    MessageDigest md = SHA256.getMessageDigest();
    md.update(key.getRoutingKey());
    md.update(localSalt);
    return md.digest();
  }

  /**
   * The segment bloom filters should only need to be written ONCE, and can all be written at once.
   * Include a checksum.
   */
  void initialWriteSegmentBloomFilters(long fileOffset) throws IOException {
    try (OutputStream cos =
        storage.writeChecksummedTo(fileOffset, totalSegmentBloomFiltersSize())) {
      for (BinaryBloomFilter segFilter : segmentFilters) {
        segFilter.writeTo(cos);
      }
    }
  }

  int totalSegmentBloomFiltersSize() {
    return perSegmentBloomFilterSizeBytes * segmentFilters.length + storage.checksumLength;
  }

  void maybeWriteMainBloomFilter(long fileOffset) throws IOException {
    synchronized (this) {
      if (!dirty) return;
      dirty = false;
    }
    innerWriteMainBloomFilter(fileOffset);
  }

  /** Write the main segment filter, which does get updated. Include a checksum. */
  void innerWriteMainBloomFilter(long fileOffset) throws IOException {
    try (OutputStream cos = storage.writeChecksummedTo(fileOffset, paddedMainBloomFilterSize())) {
      filter.writeTo(cos);
    }
  }

  /**
   * Return the on‑disk size of the main Bloom filter region, including checksum padding.
   *
   * <p>The main counting Bloom filter is stored as {@code mainBloomFilterSizeBytes} followed by the
   * storage's checksum. This method returns their sum, which is the exact length written by {@link
   * #innerWriteMainBloomFilter(long)} and expected by the corresponding read path.
   *
   * @return total number of bytes written for the main filter, i.e., raw filter size plus checksum
   *     trailer; the value is non‑negative and stable for the lifetime of the instance
   */
  public int paddedMainBloomFilterSize() {
    assert (mainBloomFilterSizeBytes == filter.getSizeBytes());
    return mainBloomFilterSizeBytes + storage.checksumLength;
  }

  /** {@inheritDoc} */
  @Override
  public boolean probablyWantKey(Key key, byte[] saltedKey) {
    if (filter.checkFilter(saltedKey)) {
      byte[] salted = localSaltKey(key);
      for (BinaryBloomFilter segmentFilter : segmentFilters) {
        if (segmentFilter.checkFilter(salted)) {
          return true;
        }
      }
    }
    return false;
  }

  /** {@inheritDoc} */
  @Override
  public short definitelyWantKey(Key key, byte[] saltedKey, ClientContext context) {
    // Caller has already called probablyWantKey(), so don't do it again.
    byte[] salted = localSaltKey(key);
    for (int i = 0; i < segmentFilters.length; i++) {
      if (segmentFilters[i].checkFilter(salted)
          && storage.segments[i].definitelyWantKey((NodeCHK) key)) {
        return fetcher.getPriorityClass();
      }
    }
    return -1;
  }

  /** {@inheritDoc} */
  @Override
  @SuppressWarnings("java:S1168")
  public SendableGet[] getRequestsForKey(Key key, byte[] saltedKey, ClientContext context) {
    // Not used by this listener; cooldown queue is not employed here.
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public boolean handleBlock(Key key, byte[] saltedKey, KeyBlock block, ClientContext context) {
    // Caller has already called probablyWantKey(), so don't do it again.
    boolean found = false;
    byte[] salted = localSaltKey(key);
    if (LOG.isDebugEnabled()) LOG.debug("handleBlock({}) on {} for {}", key, this, fetcher);
    for (int i = 0; i < segmentFilters.length; i++) {
      boolean match;
      synchronized (this) {
        match = segmentFilters[i].checkFilter(salted);
      }
      if (match) {
        try {
          found = storage.segments[i].onGotKey((NodeCHK) key, (CHKBlock) block);
        } catch (IOException e) {
          fetcher.failOnDiskError(e);
          return false;
        }
      }
    }
    if (found) {
      synchronized (this) {
        dirty = true;
      }
      filter.removeKey(saltedKey);
      if (persistent) storage.lazyWriteMetadata();
    }
    return found;
  }

  /**
   * Whether this listener participates in persistence flows.
   *
   * <p>When {@code true}, the listener requests that its owning storage write metadata lazily after
   * successful block processing (e.g., updating the main Bloom filter on disk). A {@code false}
   * value means the filters remain purely in memory.
   *
   * @return {@code true} when persistence is enabled for this instance; otherwise {@code false}
   */
  @Override
  public boolean persistent() {
    return persistent;
  }

  /**
   * Return the request priority to use for keys accepted by this listener.
   *
   * <p>The value is delegated to the {@link SplitFileFetcherStorageCallback} provided at
   * construction time so the listener remains a thin screen that does not own scheduling policy.
   *
   * @return the priority class associated with the parent fetcher
   */
  @Override
  public short getPriorityClass() {
    return fetcher.getPriorityClass();
  }

  /**
   * Unsupported for this listener: counting is not used in the current fetch strategy.
   *
   * <p>Some persistent fetches track the number of outstanding keys; this implementation does not
   * support that operation and signals it explicitly via an exception.
   *
   * @throws UnsupportedOperationException always thrown by this implementation
   */
  @Override
  public long countKeys() {
    // Not used except for persistent fetches; unsupported here.
    throw new UnsupportedOperationException();
  }

  /**
   * Return the owner that supplies this listener and related callbacks.
   *
   * @return the {@link HasKeyListener} associated with the parent fetch operation
   */
  @Override
  public HasKeyListener getHasKeyListener() {
    return fetcher.getHasKeyListener();
  }

  /**
   * Notification that the listener is being detached from the owning request.
   *
   * <p>The listener does not hold external resources and therefore performs no active cleanup.
   * Asynchronous writers may still complete; filter buffers are heap‑backed and left to GC.
   */
  @Override
  public void onRemove() {
    // Defer resource cleanup: asynchronous metadata writers may still call into
    // maybeWriteMainBloomFilter() after deregistration. The owning storage closes
    // these resources once finishing is guaranteed.
  }

  // Intentionally no explicit close() — writing jobs may still reference the filters
  // after listener removal; filters are heap-backed, so early release is unnecessary.

  /**
   * Report whether the listener has no remaining work.
   *
   * <p>This delegates to the underlying storage to determine if the associated splitfile fetch has
   * finished. A {@code true} value allows callers to retire the listener early.
   *
   * @return {@code true} when the owning storage reports completion; otherwise {@code false}
   */
  @Override
  public boolean isEmpty() {
    return storage.hasFinished();
  }

  /**
   * Indicate whether the listener is for SSK keys rather than CHK.
   *
   * <p>This implementation serves CHK content only and therefore always returns {@code false}.
   *
   * @return {@code false} for CHK‑only listeners
   */
  @Override
  public boolean isSSK() {
    return false;
  }

  /**
   * Optionally, return a single key of immediate interest.
   *
   * <p>Unused by this listener; returning {@code null} communicates that there is no special key to
   * prioritize outside the regular filtering flow.
   *
   * @return {@code null} because no single key is preferred
   */
  @Override
  @SuppressWarnings("java:S1168")
  public byte[] getWantedKey() {
    return null;
  }

  /**
   * Write immutable listener parameters that are required to reconstruct the filter state.
   *
   * <p>The method writes, in order: {@code localSalt} (32 bytes), {@code mainBloomFilterSizeBytes},
   * {@code mainBloomK}, {@code perSegmentBloomFilterSizeBytes}, and {@code perSegmentK}. It does
   * not write the main or per‑segment filter contents; those regions are handled separately using
   * check-summed blobs.
   *
   * @param dos target stream used to serialize settings; must remain open for further writes by the
   *     caller; the method does not close the stream
   * @throws IOException if any of the setting values cannot be written to the destination stream
   */
  public void writeStaticSettings(DataOutputStream dos) throws IOException {
    dos.write(localSalt);
    dos.writeInt(mainBloomFilterSizeBytes);
    dos.writeInt(mainBloomK);
    dos.writeInt(perSegmentBloomFilterSizeBytes);
    dos.writeInt(perSegmentK);
  }

  /**
   * Indicate whether the caller must re‑feed all keys to rebuild one or more filters.
   *
   * <p>After a failed checksum validation or when a new salt is introduced, this method returns
   * {@code true} until {@link #addedAllKeys()} is invoked. Callers can use it to decide whether to
   * schedule a full key scan to repopulate in‑memory structures.
   *
   * @return {@code true} when at least one Bloom filter requires regeneration from the key set;
   *     {@code false} when all filters are up‑to‑date
   */
  public boolean needsKeys() {
    return mustRegenerateMainFilter || mustRegenerateSegmentFilters;
  }

  /**
   * Mark filter reconstruction complete after all keys have been supplied.
   *
   * <p>Call this once the caller has replayed every relevant key via {@link #addKey(Key, int,
   * KeySalter)}. It clears pending regeneration flags and flips the listener into the steady state
   * where only the main counting Bloom filter is mutated as blocks arrive.
   */
  public void addedAllKeys() {
    mustRegenerateMainFilter = false;
    mustRegenerateSegmentFilters = false;
    finishedSetup = true;
  }
}

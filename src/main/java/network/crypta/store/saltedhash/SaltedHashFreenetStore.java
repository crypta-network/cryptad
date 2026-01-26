package network.crypta.store.saltedhash;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Deque;
import java.util.LinkedList;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.UnsupportedCipherException;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.keys.KeyVerifyException;
import network.crypta.keys.SSKBlock;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.FastRunnable;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.node.stats.StoreAccessStats;
import network.crypta.node.useralerts.AbstractUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.store.BlockMetadata;
import network.crypta.store.FetchOptions;
import network.crypta.store.FreenetStore;
import network.crypta.store.KeyCollisionException;
import network.crypta.store.StorableBlock;
import network.crypta.store.StoreCallback;
import network.crypta.support.Fields;
import network.crypta.support.HTMLNode;
import network.crypta.support.HexUtil;
import network.crypta.support.Ticker;
import network.crypta.support.WrapperKeepalive;
import network.crypta.support.io.Fallocate;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.NativeThread;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperManager;

/**
 * Index-less on-disk store that maps keys to slots using a salted hash.
 *
 * <p>The store uses a fixed number of slots and quadratic probing. A per-store salt (derived from
 * the master key) ensures the mapping is not predictable across nodes. A compact on-disk “slot
 * filter” (a Bloom-filter replacement) records, for each slot, whether it has been checked and the
 * first three bytes of the salted key. This allows the reader to skip most disk seeks when there is
 * no match and to avoid scanning slots known to be free.
 *
 * <p>All payload bytes are encrypted with a key derived from the routing key and salt; without the
 * routing key, the content is unrecoverable. For debugging only, {@code OPTION_SAVE_PLAINKEY} can
 * be enabled to persist the plain routing key alongside the entry; this must never be enabled in a
 * client cache.
 *
 * <p>The store optionally overflows writes to a secondary “alt” store when the primary is full. The
 * cleaner thread periodically completes, resizes, and rebuilds the slot filter after format
 * changes.
 *
 * @author sdiz
 */
public class SaltedHashFreenetStore<T extends StorableBlock> implements FreenetStore<T> {
  private static final Logger LOG = LoggerFactory.getLogger(SaltedHashFreenetStore.class);

  /** Option for saving plainkey. SECURITY: never enable this for a client cache. */
  private static final boolean OPTION_SAVE_PLAINKEY = false;

  static final int OPTION_MAX_PROBE = 5;

  private static final byte FLAG_DIRTY = 0x1;
  private static final byte FLAG_REBUILD_BLOOM = 0x2;

  /**
   * Compact per-slot index (“slot filter”).
   *
   * <p>This replaces the historical Bloom filter and indicates exactly which slots to check. Each
   * slot is represented by a 4-byte integer with the following layout:
   *
   * <ul>
   *   <li>Bit 31 ({@link #SLOT_CHECKED}) — set when the slot has been examined; if clear the
   *       content is unknown and the entry must be read.
   *   <li>Bit 30 ({@link #SLOT_OCCUPIED}) — 1 if the slot contains an entry, 0 if free.
   *   <li>Bit 29 ({@link #SLOT_NEW_BLOCK}) — 1 for entries considered “new” according to the
   *       current policy (e.g., post-local-request caching change), 0 otherwise.
   *   <li>Bit 28 ({@link #SLOT_WRONG_STORE}) — 1 when the entry was written to an alternate store.
   *   <li>Bits 0–23 — the first three bytes of the salted key.
   * </ul>
   *
   * <p>Using the filter significantly reduces disk I/O on both hits and misses.
   */
  private final ResizablePersistentIntBuffer slotFilter;

  /** If true, the slot filter is disabled and not maintained. */
  private final boolean slotFilterDisabled;

  /**
   * When true, the slot filter is treated as authoritative for checked slots. Unknown slots (bit 31
   * clear) still require reads. Disabled entirely when {@link #slotFilterDisabled} is true.
   */
  private static final boolean USE_SLOT_FILTER = true;

  private static final int SLOT_CHECKED = 1 << 31;
  private static final int SLOT_OCCUPIED = 1 << 30;
  private static final int SLOT_NEW_BLOCK = 1 << 29;
  private static final int SLOT_WRONG_STORE = 1 << 28;
  private static final String LOG_OFFSET = ", offset=";
  private static final String META_EXT = ".metadata";
  private static final String CACHE_WAS = " cache was ";
  private static final String STR_FROM = " from ";
  private static final String KEY_PROCESSED = "processed";
  private static final String KEY_TOTAL = "total";

  // Legacy debug gates removed; prefer SLF4J guards directly.

  private final File baseDir;
  private final String name;
  private final StoreCallback<T> callback;
  private final boolean collisionPossible;
  private final int headerBlockLength;
  private final int dataBlockLength;
  private final Random random;
  private final File bloomFile;

  private long storeSize;
  private int generation;
  private int flags;

  private boolean preallocate;
  // Mutable test hook: keep non-public and expose minimal accessor.
  private static volatile boolean noCleanerSleep = false;

  /** Controls whether the cleaner should skip its initial sleep (test hook). */
  public static void setNoCleanerSleep(boolean value) {
    noCleanerSleep = value;
  }

  /** true if close() has been called */
  private final AtomicBoolean closeCalled = new AtomicBoolean(false);

  /**
   * Optional overflow target for writes when this store has no free slots.
   *
   * <p>Entries written to the alternate store are flagged as “wrong store”. Callers must read from
   * both stores as appropriate; this class does not consult {@code altStore} on reads. The wiring
   * must be strictly one-way to avoid deadlocks and recursion.
   */
  private SaltedHashFreenetStore<T> altStore;

  /**
   * Sets the alternate store used for overflow writes.
   *
   * <p><strong>Locking:</strong> Do not create cycles (A→B and B→A). A bidirectional relationship
   * can deadlock and/or recurse.
   *
   * @param store destination store that must itself not have an alternate store
   * @throws IllegalArgumentException if {@code store} already has an {@code altStore}
   */
  public void setAltStore(SaltedHashFreenetStore<T> store) {
    if (store.altStore != null)
      throw new IllegalArgumentException("Target must not have an altStore - deadlock can result");
    altStore = store;
  }

  /**
   * Factory for constructing a salted-hash store from grouped parameters.
   *
   * @param params parameter object describing the store instance to create
   * @return the created store
   * @throws IOException on I/O errors creating or opening the store
   */
  public static <T extends StorableBlock> SaltedHashFreenetStore<T> construct(
      SaltedHashStoreParams<T> params) throws IOException {
    Objects.requireNonNull(params, "params");
    return new SaltedHashFreenetStore<>(params);
  }

  /**
   * Factory for constructing a salted-hash store.
   *
   * @param baseDir directory where the store files live; created if missing
   * @param name logical name; also used as a filename prefix
   * @param callback callback used to get header/data lengths and to (de-)serialize blocks
   * @param random randomness source for encryption and placement tie-breakers
   * @param maxKeys number of slots in the store (capacity)
   * @param useSlotFilter whether to enable the on-disk slot filter index
   * @param shutdownHook hook on which the store registers a close task
   * @param preallocate whether to preallocate files up to {@code maxKeys}
   * @param resizeOnStart when true, finishes any in-progress resize before returning
   * @param masterKey master key used to derive per-store salts
   * @return the created store
   * @throws IOException on I/O errors creating or opening the store
   */
  @SuppressWarnings("java:S107") // legacy delegator to params object
  public static <T extends StorableBlock> SaltedHashFreenetStore<T> construct(
      File baseDir,
      String name,
      StoreCallback<T> callback,
      Random random,
      long maxKeys,
      boolean useSlotFilter,
      SemiOrderedShutdownHook shutdownHook,
      boolean preallocate,
      boolean resizeOnStart,
      byte[] masterKey)
      throws IOException {
    return construct(
        SaltedHashStoreParams.of(
            baseDir,
            name,
            callback,
            random,
            maxKeys,
            useSlotFilter,
            shutdownHook,
            preallocate,
            resizeOnStart,
            masterKey));
  }

  private SaltedHashFreenetStore(SaltedHashStoreParams<T> params) throws IOException {
    this.baseDir = params.baseDir();
    this.name = params.name();

    this.callback = params.callback();
    collisionPossible = callback.collisionPossible();
    headerBlockLength = callback.headerLength();
    callback.fullKeyLength(); // ensure callback is initialized; length not needed here
    dataBlockLength = callback.dataLength();

    hdPadding =
        ((headerBlockLength + dataBlockLength + 512 - 1) & -512)
            - (headerBlockLength + dataBlockLength);

    this.random = params.random();
    storeSize = params.maxKeys();
    this.preallocate = params.preallocate();

    lockManager = new LockManager();

    // Create the base directory and validate the target size.
    createBaseDirIfMissing();
    validateStoreSizeLimit();

    configFile = new File(this.baseDir, name + ".config");
    boolean newStore = loadConfigAndMaybeResize(params.masterKey(), params.maxKeys());

    // Open/lock the backing files.
    newStore |= openStoreFiles(baseDir, name);

    // Bloom is obsolete; ensure it is removed with a message.
    bloomFile = new File(this.baseDir, name + ".bloom");
    initializeBloom(bloomFile);

    // Initialize or drop the on-disk slot filter structure.
    slotFilterDisabled = !params.useSlotFilter();
    slotFilter = initializeSlotFilter((int) Math.max(storeSize, prevStoreSize), newStore);

    if ((flags & FLAG_DIRTY) != 0) LOG.warn("Datastore({}) is dirty.", name);

    flags |= FLAG_DIRTY; // datastore is now dirty until flushAndClose()
    writeConfigFile();

    callback.setStore(this);
    registerShutdown(params.shutdownHook());

    cleanerThread = new Cleaner();
    cleanerStatusUserAlert = new CleanerStatusUserAlert(cleanerThread);

    // Finish all resizing before continue if requested.
    maybeCompleteResizeOnStart(params.resizeOnStart());

    // Decide whether to rebuild the slot filter now.
    maybeScheduleSlotFilterRebuild(newStore);
  }

  private void registerShutdown(SemiOrderedShutdownHook shutdownHook) {
    shutdownHook.addEarlyJob(
        new NativeThread(
            new ShutdownDB(),
            "Shutdown salted hash store",
            NativeThread.PriorityLevel.HIGH_PRIORITY.value,
            true));
  }

  /** Ensures {@code baseDir} exists and is a directory. */
  private void createBaseDirIfMissing() throws IOException {
    // Create the directory tree if missing; throw if creation fails or the path is not a directory.
    if (baseDir == null) {
      throw new IOException("Base directory is null");
    }
    if (baseDir.exists()) {
      if (!baseDir.isDirectory()) {
        throw new IOException("Base path exists but is not a directory: " + baseDir);
      }
      return;
    }
    try {
      Files.createDirectories(baseDir.toPath());
    } catch (IOException ioe) {
      throw new IOException("Failed to create base directory: " + baseDir, ioe);
    }
  }

  private void validateStoreSizeLimit() {
    if (storeSize > Integer.MAX_VALUE) { // Note: 32-bit limit due to ResizablePersistentIntBuffer.
      throw new IllegalArgumentException(
          "Store size over MAXINT not supported due to ResizablePersistentIntBuffer limitations.");
    }
  }

  private boolean loadConfigAndMaybeResize(byte[] masterKey, long maxKeys) throws IOException {
    boolean newStore = loadConfigFile(masterKey);
    if (storeSize != 0 && storeSize != maxKeys && prevStoreSize == 0) {
      // If not already resizing, start resizing to the new store size.
      prevStoreSize = storeSize;
      storeSize = maxKeys;
      writeConfigFile();
    }
    return newStore;
  }

  private void initializeBloom(File bloom) {
    // Only delete old bloom files; slot filter replaces it.
    if (bloom.exists()) {
      try {
        Files.deleteIfExists(bloom.toPath());
        LOG.info("Deleted old bloom filter for {} - obsoleted by slot filter", name);
        LOG.info(
            "Slot filters will be rebuilt; expect heavy disk access until complete, then fewer"
                + " seeks.");
      } catch (IOException ioe) {
        LOG.warn("Failed to delete obsolete bloom filter file: {}", bloom, ioe);
      }
    }
  }

  private ResizablePersistentIntBuffer initializeSlotFilter(int size, boolean newStore)
      throws IOException {
    File slotFilterFile = new File(this.baseDir, name + ".slotfilter");
    if (!slotFilterDisabled) {
      ResizablePersistentIntBuffer buf = new ResizablePersistentIntBuffer(slotFilterFile, size);
      LOG.info("Slot filter ({}) for {} is loaded (new={}).", slotFilterFile, name, buf.isNew());
      if (newStore && buf.isNew()) buf.fill(SLOT_CHECKED);
      return buf;
    } else {
      if (slotFilterFile.exists()) {
        try {
          Files.deleteIfExists(slotFilterFile.toPath());
          LOG.info(
              "Old slot filter file deleted as slot filters are disabled; keeping it could risk"
                  + " data when re-enabled.");
        } catch (IOException ioe) {
          LOG.warn(
              "Old slot filter file {} could not be deleted. If you enable slot filters later you"
                  + " might lose data; please delete it manually.",
              slotFilterFile,
              ioe);
        }
      }
      return null;
    }
  }

  private void maybeCompleteResizeOnStart(boolean resizeOnStart) {
    if (resizeOnStart && prevStoreSize != 0 && cleanerGlobalLock.tryLock()) {
      LOG.info("Resizing datastore ({})", name);
      try {
        cleanerThread.resizeStore(prevStoreSize, false);
      } finally {
        cleanerGlobalLock.unlock();
      }
      writeConfigFile();
    }
  }

  private void maybeScheduleSlotFilterRebuild(boolean newStore) {
    if (((!slotFilterDisabled) && slotFilter.isNew()) && !newStore) {
      flags |= FLAG_REBUILD_BLOOM;
      LOG.info("Rebuilding slot filter because it is new");
    } else if ((flags & FLAG_REBUILD_BLOOM) != 0) {
      LOG.info("Slot filter still needs rebuilding");
    }
  }

  private boolean started = false;

  /**
   * Starts the store and the background cleaner thread.
   *
   * <p>If initialization can complete quickly, or {@code longStart} is {@code true}, the method
   * performs any required file growth and schedules the cleaner. When {@code longStart} is {@code
   * false} and a slow resize/pad is required, the method returns early without performing it so the
   * caller can defer work (e.g., on a UI thread). Subsequent calls are idempotent.
   *
   * @param ticker optional scheduler used to start the cleaner asynchronously; when {@code null}
   *     the cleaner is started directly
   * @param longStart whether slow operations (e.g., file padding) are allowed inline
   * @return {@code false} when initialization completed or was scheduled; {@code true} when already
   *     started or when heavy work was deferred because {@code longStart} was {@code false}
   * @throws IOException on I/O errors
   */
  public boolean start(Ticker ticker, boolean longStart) throws IOException {

    if (started) return true;

    if (!slotFilterDisabled) slotFilter.start(ticker);

    long curStoreFileSize = hdRAF.length();

    long curMetaFileSize = metaRAF.length();

    // If prevStoreSize is nonzero, that means that we are either shrinking or
    // growing. Either way, the file size should be between the old size and the
    // new size. If it is not, we should pad it until it is.

    long smallerSize = storeSize;
    if (prevStoreSize < storeSize && prevStoreSize > 0) smallerSize = prevStoreSize;

    if ((smallerSize * (headerBlockLength + dataBlockLength + hdPadding) > curStoreFileSize)
        || (smallerSize * Entry.METADATA_LENGTH > curMetaFileSize)) {
      // Pad it up to the minimum size before proceeding.
      if (longStart) {
        setStoreFileSize(storeSize);
        curStoreFileSize = hdRAF.length();
        curMetaFileSize = metaRAF.length();
      } else return true;
    }

    // Otherwise the resize will be completed by the Cleaner thread.
    // However, we do still need to set storeFileOffsetReady

    storeFileOffsetReady =
        Math.min(
            curStoreFileSize / (headerBlockLength + dataBlockLength + hdPadding),
            curMetaFileSize / Entry.METADATA_LENGTH);

    if (ticker == null) {
      cleanerThread.start();
    } else
      ticker.queueTimedJob(
          (FastRunnable) cleanerThread::start, "Start cleaner thread", 0, true, false);

    started = true;

    return false;
  }

  /**
   * Fetches a block by its routing key.
   *
   * <p>The lookup uses the salted-hash slots and the slot filter to minimize disk I/O. On a hit,
   * the entry is decrypted and verified. This implementation does not promote entries, so {@code
   * dontPromote} is accepted for interface compatibility and ignored.
   *
   * @param routingKey plain routing key used to derive encryption and placement
   * @param fullKey full key material provided by the caller
   * @param dontPromote ignored by this implementation
   * @param canReadClientCache whether the caller may read from the client cache (passed to
   *     callback)
   * @param canReadSlashdotCache whether the caller may read from the slashdot cache (callback)
   * @param ignoreOldBlocks when {@code true}, entries marked as old are treated as misses
   * @param meta optional metadata sink that is populated on success
   * @return the block on success; {@code null} on miss or verification failure
   * @throws IOException on I/O errors
   */
  @Override
  @SuppressWarnings("java:S107") // delegator to FetchOptions overload
  public T fetch(
      byte[] routingKey,
      byte[] fullKey,
      boolean dontPromote,
      boolean canReadClientCache,
      boolean canReadSlashdotCache,
      boolean ignoreOldBlocks,
      BlockMetadata meta)
      throws IOException {
    return fetch(
        routingKey,
        fullKey,
        new FetchOptions(
            dontPromote, canReadClientCache, canReadSlashdotCache, ignoreOldBlocks, meta));
  }

  @Override
  public T fetch(byte[] routingKey, byte[] fullKey, FetchOptions options) throws IOException {
    Objects.requireNonNull(options, "options");
    if (LOG.isDebugEnabled())
      LOG.debug("Fetch {} for {}", HexUtil.bytesToHex(routingKey), callback);

    if (!tryAcquireConfigReadLock()) return null;
    byte[] digestedKey = cipherManager.getDigestedKey(routingKey);
    try {
      Map<Long, Condition> lockMap = lockDigestedKey(digestedKey, true);
      if (lockMap.isEmpty()) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Fetch lock unavailable for key: {}, shutting down?", HexUtil.bytesToHex(routingKey));
        return null;
      }
      try {
        return fetchLocked(digestedKey, routingKey, fullKey, options);
      } finally {
        unlockDigestedKey(digestedKey, true, lockMap);
      }
    } finally {
      configLock.readLock().unlock();
    }
  }

  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  private boolean tryAcquireConfigReadLock() throws IOException {
    try {
      int retry = 0;
      while (!configLock.readLock().tryLock(2, TimeUnit.SECONDS)) {
        if (shutdown) return false;
        if (retry++ > 10) throw new IOException("lock timeout (20s)");
      }
      return true;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("interrupted: " + e);
    }
  }

  private T fetchLocked(byte[] digestedKey, byte[] routingKey, byte[] fullKey, FetchOptions options)
      throws IOException {
    Entry entry = probeEntry(digestedKey, routingKey, true);
    if (entry == null) {
      misses.incrementAndGet();
      return null;
    }

    if ((entry.flag & Entry.ENTRY_NEW_BLOCK) == 0) {
      if (options.ignoreOldBlocks()) {
        LOG.info("Ignoring old block");
        return null;
      }
      if (options.meta() != null) options.meta().setOldBlock();
    }

    try {
      T block =
          entry.getStorableBlock(
              routingKey,
              fullKey,
              options.canReadClientCache(),
              options.canReadSlashdotCache(),
              options.meta(),
              null);
      if (block == null) {
        misses.incrementAndGet();
        return null;
      }
      hits.incrementAndGet();
      return block;
    } catch (KeyVerifyException e) {
      LOG.debug("key verification exception", e);
      misses.incrementAndGet();
      return null;
    }
  }

  /**
   * Probes candidate slots for an entry matching the provided key.
   *
   * <p>This method does not acquire any slot locks; callers must lock the relevant offsets before
   * calling. When {@code withData} is {@code true}, it also reads header+data and attempts
   * decryption; otherwise it reads metadata only.
   *
   * @param digestedKey salted/digested routing key used for slot calculation
   * @param routingKey plain routing key used for decryption/verification; required when {@code
   *     withData} is {@code true}
   * @param withData whether to read and decrypt the entry payload if a candidate is found
   * @return the matching {@code Entry}, or {@code null} when not found or verification fails
   * @throws IOException on I/O errors
   */
  private Entry probeEntry(byte[] digestedKey, byte[] routingKey, boolean withData)
      throws IOException {

    Entry entry = probeEntry0(digestedKey, routingKey, storeSize, withData);

    if (entry == null && prevStoreSize != 0)
      entry = probeEntry0(digestedKey, routingKey, prevStoreSize, withData);

    return entry;
  }

  private Entry probeEntry0(
      byte[] digestedKey, byte[] routingKey, long probeStoreSize, boolean withData)
      throws IOException {
    Entry entry;
    long[] offset = getOffsetFromDigestedKey(digestedKey, probeStoreSize);

    for (int i = 0; i < offset.length; i++) {
      if (LOG.isTraceEnabled()) LOG.trace("probing for i={}" + LOG_OFFSET + "{}", i, offset[i]);

      try {
        if (storeFileOffsetReady == -1 || offset[i] < this.storeFileOffsetReady) {
          entry = readEntry(offset[i], digestedKey, routingKey, withData);
          if (entry != null) return entry;
        }
      } catch (EOFException e) {
        if (prevStoreSize == 0) { // may occur on store shrinking
          LOG.error("EOFException on probeEntry", e);
        }
      }
    }
    return null;
  }

  /**
   * Inserts or updates a block in the store.
   *
   * <p>If an entry with the same key exists, the behavior depends on {@code overwrite}. When the
   * store is full, the writing may be directed to the alternate store (if configured). The {@code
   * isOldBlock} flag controls how the “new block” bit is set in metadata.
   *
   * @param block storable block being persisted
   * @param data serialized block data bytes; length must equal the configured data size
   * @param header serialized block header bytes; length must equal the configured header size
   * @param overwrite whether to overwrite an existing non-identical entry; when {@code false}, a
   *     collision raises an exception
   * @param isOldBlock whether the entry should be marked as “old” (not considered cacheable for
   *     certain policies)
   * @throws IOException on I/O errors
   * @throws KeyCollisionException when a different entry with the same key exists and {@code
   *     overwrite} is {@code false}
   */
  @Override
  public void put(T block, byte[] data, byte[] header, boolean overwrite, boolean isOldBlock)
      throws IOException, KeyCollisionException {
    put(block, data, header, overwrite, isOldBlock, false);
  }

  /**
   * Inserts or updates a block with explicit control over the “wrong store” flag.
   *
   * <p>Identical to {@link #put(StorableBlock, byte[], byte[], boolean, boolean)} but allows the
   * caller to mark the entry as having been written to an alternate store.
   *
   * @param block storable block being persisted
   * @param data serialized block data bytes
   * @param header serialized block header bytes
   * @param overwrite whether to overwrite an existing non-identical entry
   * @param isOldBlock whether the entry should be marked as “old”
   * @param wrongStore whether the entry is being written to an alternate store
   * @return {@code true} if the operation completed successfully in this store. This includes both
   *     cases where bytes were written and cases where the identical entry already existed (and may
   *     have had metadata updated). Returns {@code false} only when the operation was intentionally
   *     deferred due to locking or scheduling semantics.
   * @throws IOException on I/O errors
   * @throws KeyCollisionException when a different entry with the same key exists and overwrite is
   *     not permitted
   */
  public boolean put(
      T block,
      byte[] data,
      byte[] header,
      boolean overwrite,
      boolean isOldBlock,
      boolean wrongStore)
      throws IOException, KeyCollisionException {
    byte[] routingKey = block.getRoutingKey();
    byte[] fullKey = block.getFullKey();

    if (LOG.isDebugEnabled()) LOG.debug("Putting {} ({})", HexUtil.bytesToHex(routingKey), name);

    if (!tryAcquireConfigReadLock()) return true;
    byte[] digestedKey = cipherManager.getDigestedKey(routingKey);
    try {
      Map<Long, Condition> lockMap = lockDigestedKey(digestedKey, false);
      if (lockMap.isEmpty()) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Put lock unavailable for key: {}, shutting down?", HexUtil.bytesToHex(routingKey));
        return false;
      }
      try {
        // Check for an existing entry and handle it first.
        Entry oldEntry = probeEntry(digestedKey, routingKey, false);
        if (oldEntry != null && !oldEntry.isFree()) {
          return handleExistingEntryWhenPresent(
              new ExistingEntryParams<>(oldEntry, block, overwrite, isOldBlock, wrongStore),
              new KeyContext(digestedKey, routingKey, fullKey),
              new EntryData(header, data));
        }

        Entry entry = new Entry(routingKey, header, data, !isOldBlock, wrongStore);
        long[] offset = entry.getOffset();

        WrongStoreScanResult scan = scanOffsetsForWrite(offset, entry, digestedKey);
        if (scan.written()) return true;

        if ((!wrongStore)
            && altStore != null
            && tryWriteToAltStore(block, data, header, overwrite, isOldBlock)) {
          return true;
        }

        Integer indexToOverwrite =
            chooseOverwriteIndex(wrongStore, scan.wrongStoreCount(), scan.firstWrongStoreIndex());
        if (indexToOverwrite == null)
          return false; // Force overwriting to happen in the right store.

        overwriteAtIndex(offset, indexToOverwrite, entry, digestedKey);
        return true;
      } finally {
        unlockDigestedKey(digestedKey, false, lockMap);
      }
    } finally {
      configLock.readLock().unlock();
    }
  }

  private boolean handleExistingEntryWhenPresent(
      ExistingEntryParams<T> params, KeyContext keyContext, EntryData entryData)
      throws IOException, KeyCollisionException {
    long oldOffset = params.oldEntry().curOffset;
    try {
      if (!collisionPossible) {
        // When collisions are impossible, confirming the existing entry is enough for callers
        // (including alt-store writes) to consider the operation successful. Update metadata if
        // needed, but always report success to avoid duplicate writes in the primary store.
        updateNewBlockFlagIfNeeded(
            params.oldEntry(),
            keyContext.digestedKey(),
            keyContext.routingKey(),
            oldOffset,
            params.isOldBlock());
        return true;
      }
      params.oldEntry().setHD(readHD(oldOffset)); // read from disk
      T oldBlock =
          params
              .oldEntry()
              .getStorableBlock(
                  keyContext.routingKey(),
                  keyContext.fullKey(),
                  false,
                  false,
                  null,
                  (params.block() instanceof SSKBlock sskb) ? sskb.getPubKey() : null);
      if (params.block().equals(oldBlock)) {
        return handleAlreadyStored(
            params.oldEntry(), params.isOldBlock(), keyContext.digestedKey(), oldOffset);
      } else if (!params.overwrite()) {
        throw new KeyCollisionException();
      }
    } catch (KeyVerifyException _) {
      // ignore
    }

    // Overwrite the old offset with the same key
    Entry entry =
        new Entry(
            keyContext.routingKey(),
            entryData.header(),
            entryData.data(),
            !params.isOldBlock(),
            params.wrongStore());
    writeEntry(entry, keyContext.digestedKey(), oldOffset);
    if (params.oldEntry().generation != generation) keyCount.incrementAndGet();
    return true;
  }

  private void updateNewBlockFlagIfNeeded(
      Entry oldEntry, byte[] digestedKey, byte[] routingKey, long oldOffset, boolean isOldBlock)
      throws IOException {
    if ((oldEntry.flag & Entry.ENTRY_NEW_BLOCK) == 0 && !isOldBlock) {
      // Re-read with data for a safe in-place metadata update; may return null if verification
      // fails.
      oldEntry = readEntry(oldEntry.curOffset, digestedKey, routingKey, true);
      if (oldEntry == null) {
        // Entry no longer matches or could not be decrypted; skip flag update safely.
        if (LOG.isDebugEnabled()) LOG.debug("Skipping flag update; entry could not be verified");
        return; // no change performed
      }
      // Currently flagged as an old block; update and persist.
      oldEntry.flag |= Entry.ENTRY_NEW_BLOCK;
      if (LOG.isDebugEnabled()) LOG.debug("Updating entry flag from old to new after verify");
      oldEntry.storeSize = storeSize;
      writeEntry(oldEntry, digestedKey, oldOffset);
    }
  }

  private boolean handleAlreadyStored(
      Entry oldEntry, boolean isOldBlock, byte[] digestedKey, long oldOffset) throws IOException {
    if (LOG.isTraceEnabled()) LOG.trace("Block already stored");
    if ((oldEntry.flag & Entry.ENTRY_NEW_BLOCK) == 0 && !isOldBlock) {
      // Currently flagged as an old block
      oldEntry.flag |= Entry.ENTRY_NEW_BLOCK;
      if (LOG.isDebugEnabled())
        LOG.debug("Updating entry flag from old to new on already stored entry");
      oldEntry.storeSize = storeSize;
      writeEntry(oldEntry, digestedKey, oldOffset);
    }
    // Report success: the block is already present (and metadata may have been updated).
    return true;
  }

  private record WrongStoreScanResult(
      int firstWrongStoreIndex, int wrongStoreCount, boolean written) {
    static WrongStoreScanResult createWritten() {
      return new WrongStoreScanResult(-1, 0, true);
    }
  }

  private WrongStoreScanResult scanOffsetsForWrite(long[] offset, Entry entry, byte[] digestedKey)
      throws IOException {
    int firstWrongStoreIndex = -1;
    int wrongStoreCount = 0;
    for (int i = 0; i < offset.length; i++) {
      if (offset[i] < storeFileOffsetReady) {
        long flag = getFlag(offset[i]);
        if ((flag & Entry.ENTRY_FLAG_OCCUPIED) == 0) {
          // write to free block
          if (LOG.isTraceEnabled())
            LOG.trace("probing, write to i={}" + LOG_OFFSET + "{}", i, offset[i]);
          writeEntry(entry, digestedKey, offset[i]);
          keyCount.incrementAndGet();
          onWrite();
          return WrongStoreScanResult.createWritten();
        } else if (((flag & Entry.ENTRY_WRONG_STORE) == Entry.ENTRY_WRONG_STORE)) {
          if (wrongStoreCount == 0) firstWrongStoreIndex = i;
          wrongStoreCount++;
        }
      }
    }
    return new WrongStoreScanResult(firstWrongStoreIndex, wrongStoreCount, false);
  }

  private boolean tryWriteToAltStore(
      T block, byte[] data, byte[] header, boolean overwrite, boolean isOldBlock)
      throws IOException, KeyCollisionException {
    if (altStore.put(block, data, header, overwrite, isOldBlock, true)) {
      if (LOG.isDebugEnabled())
        LOG.debug("Successfully wrote block to wrong store {} on {}", altStore, this);
      return true;
    } else {
      if (LOG.isDebugEnabled()) LOG.debug("Writing to wrong store {} on {} failed", altStore, this);
      return false;
    }
  }

  private Integer chooseOverwriteIndex(
      boolean wrongStore, int wrongStoreCount, int firstWrongStoreIndex) {
    if (wrongStore) {
      // Distribute overwriting evenly between the right store and the wrong store.
      if (random.nextInt(OPTION_MAX_PROBE + wrongStoreCount) < wrongStoreCount) {
        // Allow the overwriting to happen in the wrong store.
        return firstWrongStoreIndex;
      } else {
        // Force the overwriting to happen in the right store.
        return null;
      }
    } else {
      // By default, overwrite offset[0] when not writing to the wrong store.
      return 0;
    }
  }

  private void overwriteAtIndex(
      long[] offset, int indexToOverwrite, Entry entry, byte[] digestedKey) throws IOException {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "collision, write to i={}" + LOG_OFFSET + "{}",
          indexToOverwrite,
          offset[indexToOverwrite]);
    Entry oldEntry = readEntry(offset[indexToOverwrite], null, null, false);
    writeEntry(entry, digestedKey, offset[indexToOverwrite]);
    if (oldEntry != null && oldEntry.generation != generation) keyCount.incrementAndGet();
    onWrite();
  }

  private void onWrite() {
    // Increment write counter; threshold-based boolean was unused by callers.
    writes.incrementAndGet();
  }

  // ------------- Entry I/O
  // meta-data file
  private File metaFile;
  private RandomAccessFile metaRAF;
  private FileChannel metaFC;
  private FileLock metaLock;
  // header+data file
  private File hdFile;
  private RandomAccessFile hdRAF;
  private FileChannel hdFC;
  private FileLock hdLock;
  private final int hdPadding;

  /**
   * Data entry
   *
   * <pre>
   *  META-DATA BLOCK
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *       |0|1|2|3|4|5|6|7|8|9|A|B|C|D|E|F|
   *  +----+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |0000|                               |
   *  +----+     Digested Routing Key      |
   *  |0010|                               |
   *  +----+-------------------------------+
   *  |0020|       Data Encrypt IV         |
   *  +----+---------------+---------------+
   *  |0030|     Flag      |  Store Size   |
   *  +----+---------------+---------------+
   *  |0040|       Plain Routing Key       |
   *  |0050| (Only if ENTRY_FLAG_PLAINKEY) |
   *  +----+-------+-----------------------+
   *  |0060|  Gen  |    Reserved           |
   *  +----+-------+-----------------------+
   *  |0070|            Reserved           |
   *  +----+-------------------------------+
   *
   *  Gen = Generation
   * </pre>
   */
  class Entry {
    /** Flag for occupied space */
    private static final long ENTRY_FLAG_OCCUPIED = 0x00000001L;

    /** Flag for a plain key available */
    private static final long ENTRY_FLAG_PLAINKEY = 0x00000002L;

    /** Flag for block added after we stopped caching local (and high htl) requests */
    private static final long ENTRY_NEW_BLOCK = 0x00000004L;

    /** Flag set if the block was stored in the wrong datastore i.e., store instead of cache */
    private static final long ENTRY_WRONG_STORE = 0x00000008L;

    /** Control block length */
    private static final int METADATA_LENGTH = 0x80;

    byte[] plainRoutingKey;
    byte[] digestedRoutingKey;
    byte[] dataEncryptIV;
    private long flag;
    private long storeSize;
    private int generation;
    byte[] header;
    byte[] data;

    boolean isEncrypted;
    private long curOffset = -1;

    private Entry() {}

    private Entry(ByteBuffer metaDataBuf, ByteBuffer hdBuf) {
      assert metaDataBuf.remaining() == METADATA_LENGTH;

      digestedRoutingKey = new byte[0x20];
      metaDataBuf.get(digestedRoutingKey);

      dataEncryptIV = new byte[0x10];
      metaDataBuf.get(dataEncryptIV);

      flag = metaDataBuf.getLong();
      storeSize = metaDataBuf.getLong();

      if ((flag & ENTRY_FLAG_PLAINKEY) != 0) {
        plainRoutingKey = new byte[0x20];
        metaDataBuf.get(plainRoutingKey);
      }

      metaDataBuf.position(0x60);
      generation = metaDataBuf.getInt();

      isEncrypted = true;

      if (hdBuf != null) setHD(hdBuf);
    }

    /**
     * Sets {@code header} and {@code data} arrays from the provided buffer.
     *
     * <p>Used when the metadata was constructed first and the payload needs to be attached.
     *
     * @param hdBuf buffer containing {@code headerBlockLength + dataBlockLength + hdPadding} bytes
     */
    private void setHD(ByteBuffer hdBuf) {
      assert hdBuf.remaining() == headerBlockLength + dataBlockLength + hdPadding;
      assert isEncrypted;

      header = new byte[headerBlockLength];
      hdBuf.get(header);

      data = new byte[dataBlockLength];
      hdBuf.get(data);
    }

    /**
     * Creates a new entry from the plain routing key and serialized payload.
     *
     * @param plainRoutingKey plain routing key (un-digested)
     * @param header serialized header bytes (copied)
     * @param data serialized data bytes (copied)
     * @param newBlock whether the entry should be marked as “new”
     * @param wrongStore whether the entry is flagged as stored in the alternate store
     */
    private Entry(
        byte[] plainRoutingKey, byte[] header, byte[] data, boolean newBlock, boolean wrongStore) {
      this.plainRoutingKey = plainRoutingKey;

      flag = ENTRY_FLAG_OCCUPIED;
      if (newBlock) flag |= ENTRY_NEW_BLOCK;
      if (wrongStore) flag |= ENTRY_WRONG_STORE;
      this.storeSize = SaltedHashFreenetStore.this.storeSize;
      this.generation = SaltedHashFreenetStore.this.generation;

      // header/data will be overwritten in encrypt()/decrypt(),
      // let's make a copy here
      this.header = Arrays.copyOf(header, headerBlockLength);
      this.data = Arrays.copyOf(data, dataBlockLength);

      if (OPTION_SAVE_PLAINKEY) {
        flag |= ENTRY_FLAG_PLAINKEY;
      }

      isEncrypted = false;
    }

    private ByteBuffer toMetaDataBuffer() {
      ByteBuffer out = ByteBuffer.allocate(METADATA_LENGTH);
      cipherManager.encrypt(this, random);

      out.put(getDigestedRoutingKey());
      out.put(dataEncryptIV);
      out.putLong(flag);
      out.putLong(storeSize);

      if ((flag & ENTRY_FLAG_PLAINKEY) != 0 && plainRoutingKey != null) {
        assert plainRoutingKey.length == 0x20;
        out.put(plainRoutingKey);
      }

      out.position(0x60);
      out.putInt(generation);

      out.position(0);
      return out;
    }

    private ByteBuffer toHDBuffer() {
      if (header == null || data == null) return null;

      assert isEncrypted; // should have encrypted to get dataEncryptIV in the control buffer
      assert header.length == headerBlockLength;
      assert data.length == dataBlockLength;

      ByteBuffer out = ByteBuffer.allocate(headerBlockLength + dataBlockLength + hdPadding);
      out.put(header);
      out.put(data);

      out.position(0);
      return out;
    }

    private T getStorableBlock(
        byte[] routingKey,
        byte[] fullKey,
        boolean canReadClientCache,
        boolean canReadSlashdotCache,
        BlockMetadata meta,
        DSAPublicKey knownKey)
        throws KeyVerifyException {
      if (isFree() || header == null || data == null) return null; // this is a free block
      if (!cipherManager.decrypt(this, routingKey)) return null;

      T block =
          callback.construct(
              new StoreCallback.BlockPayload(data, header, routingKey, fullKey),
              new StoreCallback.ConstructOptions(canReadClientCache, canReadSlashdotCache, meta),
              knownKey);
      byte[] blockRoutingKey = block.getRoutingKey();

      if (!Arrays.equals(blockRoutingKey, routingKey)) {
        // can't recover, as decrypt() depends on a correct route key
        return null;
      }

      return block;
    }

    private long[] getOffset() {
      if (digestedRoutingKey != null)
        return getOffsetFromDigestedKey(digestedRoutingKey, storeSize);
      else
        return getOffsetFromDigestedKey(cipherManager.getDigestedKey(plainRoutingKey), storeSize);
    }

    private boolean isFree() {
      return (flag & ENTRY_FLAG_OCCUPIED) == 0;
    }

    @SuppressWarnings("java:S1168")
    byte[] getDigestedRoutingKey() {
      if (digestedRoutingKey == null) {
        if (plainRoutingKey == null) {
          return null;
        } else {
          digestedRoutingKey = cipherManager.getDigestedKey(plainRoutingKey);
        }
      }
      return digestedRoutingKey;
    }

    public int getSlotFilterEntry(byte[] digestedRoutingKey, long flags) {
      int value =
          (digestedRoutingKey[2] & 0xFF)
              + ((digestedRoutingKey[1] & 0xFF) << 8)
              + ((digestedRoutingKey[0] & 0xFF) << 16);
      value |= SLOT_CHECKED;
      if ((flags & ENTRY_FLAG_OCCUPIED) != 0) value |= SLOT_OCCUPIED;
      if ((flags & ENTRY_NEW_BLOCK) != 0) value |= SLOT_NEW_BLOCK;
      if ((flags & ENTRY_WRONG_STORE) != 0) value |= SLOT_WRONG_STORE;
      return value;
    }

    public int getSlotFilterEntry() {
      return getSlotFilterEntry(getDigestedRoutingKey(), flag);
    }
  }

  /**
   * Checks whether a slot-filter value likely matches a given digested key.
   *
   * @param value slot-filter entry
   * @param digestedRoutingKey salted/digested routing key
   * @return {@code true} if the filter indicates a likely match; {@code false} if the slot is
   *     known-free, unknown, or the prefix does not match
   */
  public boolean slotCacheLikelyMatch(int value, byte[] digestedRoutingKey) {
    if ((value & (SLOT_CHECKED)) == 0) return false;
    if ((value & (SLOT_OCCUPIED)) == 0) return false;
    int wanted =
        (digestedRoutingKey[2] & 0xFF)
            + ((digestedRoutingKey[1] & 0xFF) << 8)
            + ((digestedRoutingKey[0] & 0xFF) << 16);
    int got = value & 0xFFFFFF;
    return wanted == got;
  }

  private long translateSlotFlagsToEntryFlags(int cache) {
    long ret = 0;
    if ((cache & SLOT_OCCUPIED) != 0) ret |= Entry.ENTRY_FLAG_OCCUPIED;
    if ((cache & SLOT_NEW_BLOCK) != 0) ret |= Entry.ENTRY_NEW_BLOCK;
    if ((cache & SLOT_WRONG_STORE) != 0) ret |= Entry.ENTRY_WRONG_STORE;
    return ret;
  }

  private boolean slotCacheIsFree(int value) {
    return (value & SLOT_OCCUPIED) == 0;
  }

  private volatile long storeFileOffsetReady = -1;

  /**
   * Opens and exclusively locks the metadata and data files for this store.
   *
   * <p>Creates the files when they do not exist and returns whether this is a new store. Acquires
   * process-wide locks on both channels to prevent concurrent writers.
   *
   * @param baseDir directory containing the store files
   * @param name filename prefix used for the pair of files
   * @return {@code true} if files were newly created; {@code false} otherwise
   * @throws IOException on I/O errors opening or locking the files
   */
  private boolean openStoreFiles(File baseDir, String name) throws IOException {
    metaFile = new File(baseDir, name + META_EXT);
    hdFile = new File(baseDir, name + ".hd");

    boolean newStore = !metaFile.exists() || !hdFile.exists();

    metaRAF = new RandomAccessFile(metaFile, "rw");
    metaFC = metaRAF.getChannel();

    try {
      // Hold the lock for the life of this channel; released on close.
      metaLock = metaFC.lock();
    } catch (OverlappingFileLockException ex) {
      throw new IllegalStateException(
          "Could not acquire lock for file " + baseDir.toPath().resolve(name + META_EXT), ex);
    }

    hdRAF = new RandomAccessFile(hdFile, "rw");
    hdFC = hdRAF.getChannel();
    try {
      // Hold the lock for the life of this channel; released on close.
      hdLock = hdFC.lock();
    } catch (OverlappingFileLockException ex) {
      throw new IllegalStateException(
          "Could not acquire lock for file " + baseDir.toPath().resolve(name + ".hd"), ex);
    }

    return newStore;
  }

  /**
   * Reads an entry's metadata (and optionally payload) from the disk at a given slot.
   *
   * <p>Callers must acquire the necessary slot locks before invoking. When {@code routingKey} is
   * non-{@code null}, a free slot or a digested-key mismatch returns {@code null}. When {@code
   * withData} is {@code true}, the method also reads header+data and attempts decryption, returning
   * {@code null} on decryption failure. The slot filter is updated when the observed state differs
   * from its cached value.
   *
   * @param offset slot index
   * @param digestedRoutingKey salted/digested key used to check for a match; may be {@code null}
   * @param routingKey plain routing key used for decryption; may be {@code null} to read metadata
   *     only
   * @param withData whether to read and decrypt header+data if a candidate looks plausible
   * @return the populated {@code Entry} on success; {@code null} when no match
   * @throws IOException on I/O errors
   */
  private Entry readEntry(
      long offset, byte[] digestedRoutingKey, byte[] routingKey, boolean withData)
      throws IOException {
    if (offset >= Integer.MAX_VALUE) throw new IllegalArgumentException();

    CacheState cacheState = getCacheState(digestedRoutingKey, offset);
    if (USE_SLOT_FILTER && cacheState.valid() && !cacheState.likelyMatch()) return null;
    logCacheLikelihood(cacheState);

    Entry entry = readMetadata(offset);
    updateSlotFilterIfChanged(offset, cacheState, entry);

    if (routingKey != null) {
      if (shouldReturnNullForFreeOrMismatchedKey(entry, cacheState, digestedRoutingKey, offset))
        return null;

      if (cacheState.valid() && !cacheState.likelyMatch()) {
        LOG.error(
            "False NEGATIVE from slot cache on slot {}" + CACHE_WAS + "{}",
            offset,
            cacheState.cache());
        bloomFalsePos.incrementAndGet();
      }

      if (withData && !decryptEntryData(entry, routingKey, cacheState, offset)) return null;
    }

    return entry;
  }

  private boolean decryptEntryData(
      Entry entry, byte[] routingKey, CacheState cacheState, long offset) throws IOException {
    ByteBuffer hdBuf = readHD(offset);
    entry.setHD(hdBuf);
    boolean decrypted = cipherManager.decrypt(entry, routingKey);
    if (!decrypted) {
      if (LOG.isDebugEnabled() && cacheState.valid() && cacheState.likelyMatch())
        LOG.debug(
            "True positive but decrypt failed on slot {}" + CACHE_WAS + "{}",
            offset,
            cacheState.cache());
      return false;
    } else {
      if (LOG.isDebugEnabled() && cacheState.valid() && cacheState.likelyMatch())
        LOG.debug("True positive!");
    }
    return true;
  }

  private boolean shouldReturnNullForFreeOrMismatchedKey(
      Entry entry, CacheState cs, byte[] digestedRoutingKey, long offset) {
    if (entry.isFree()) {
      if (cs.valid() && !cs.likelyMatch() && !slotCacheIsFree(cs.cache())) {
        LOG.error(
            "Slot falsely identified as non-free on slot {}" + CACHE_WAS + "{}",
            offset,
            cs.cache());
        bloomFalsePos.incrementAndGet();
      } else if (LOG.isDebugEnabled()
          && cs.valid()
          && !cs.likelyMatch()
          && slotCacheIsFree(cs.cache())) LOG.debug("Slot filter true negative: free slot");
      return true;
    }
    if (!Arrays.equals(digestedRoutingKey, entry.digestedRoutingKey)) {
      if (cs.valid() && cs.likelyMatch()) {
        LOG.info(
            "False positive from slot cache on slot {}" + CACHE_WAS + "{}", offset, cs.cache());
        bloomFalsePos.incrementAndGet();
      } else if (LOG.isDebugEnabled() && cs.valid())
        LOG.debug("Slot filter true negative: key mismatch");
      return true;
    }
    return false;
  }

  private void updateSlotFilterIfChanged(long offset, CacheState cs, Entry entry) {
    int trueCache = entry.getSlotFilterEntry();
    if (trueCache != cs.cache() && !slotFilterDisabled) {
      if (cs.valid())
        LOG.error(
            "Slot cache has changed for slot {}" + STR_FROM + "{} to {}",
            offset,
            cs.cache(),
            trueCache);
      try {
        slotFilter.put((int) offset, trueCache);
      } catch (IOException e) {
        LOG.error("Slot filter update failed after cache change: {}", e, e);
      }
    }
  }

  private Entry readMetadata(long offset) throws IOException {
    ByteBuffer mbf = ByteBuffer.allocate(Entry.METADATA_LENGTH);
    do {
      int status = metaFC.read(mbf, Entry.METADATA_LENGTH * offset + mbf.position());
      if (status == -1) {
        LOG.error("Failed to access offset {}", offset);
        throw new EOFException();
      }
    } while (mbf.hasRemaining());
    mbf.flip();
    Entry entry = new Entry(mbf, null);
    entry.curOffset = offset;
    return entry;
  }

  private void logCacheLikelihood(CacheState cs) {
    if (cs.valid && LOG.isDebugEnabled()) {
      if (cs.likelyMatch) LOG.debug("Likely match");
      else LOG.debug("Unlikely match");
    }
  }

  private CacheState getCacheState(byte[] digestedRoutingKey, long offset) {
    if (digestedRoutingKey == null || slotFilterDisabled) return new CacheState(0, false, false);
    int cache = slotFilter.get((int) offset);
    boolean validCache = (cache & SLOT_CHECKED) != 0;
    boolean likelyMatch = slotCacheLikelyMatch(cache, digestedRoutingKey);
    return new CacheState(cache, validCache, likelyMatch);
  }

  private record CacheState(int cache, boolean valid, boolean likelyMatch) {}

  private record KeyContext(byte[] digestedKey, byte[] routingKey, byte[] fullKey) {
    @Override
    public boolean equals(Object other) {
      if (this == other) return true;
      if (!(other
          instanceof
          KeyContext(byte[] otherDigestedKey, byte[] otherRoutingKey, byte[] otherFullKey)))
        return false;
      return Arrays.equals(digestedKey, otherDigestedKey)
          && Arrays.equals(routingKey, otherRoutingKey)
          && Arrays.equals(fullKey, otherFullKey);
    }

    @Override
    public int hashCode() {
      int result = Arrays.hashCode(digestedKey);
      result = 31 * result + Arrays.hashCode(routingKey);
      result = 31 * result + Arrays.hashCode(fullKey);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "KeyContext[digestedKey="
          + Arrays.toString(digestedKey)
          + ", routingKey="
          + Arrays.toString(routingKey)
          + ", fullKey="
          + Arrays.toString(fullKey)
          + "]";
    }
  }

  private record EntryData(byte[] header, byte[] data) {
    @Override
    public boolean equals(Object other) {
      if (this == other) return true;
      if (!(other instanceof EntryData(byte[] otherHeader, byte[] otherData))) return false;
      return Arrays.equals(header, otherHeader) && Arrays.equals(data, otherData);
    }

    @Override
    public int hashCode() {
      int result = Arrays.hashCode(header);
      result = 31 * result + Arrays.hashCode(data);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "EntryData[header="
          + Arrays.toString(header)
          + ", data="
          + Arrays.toString(data)
          + "]";
    }
  }

  private record ExistingEntryParams<T extends StorableBlock>(
      SaltedHashFreenetStore<T>.Entry oldEntry,
      T block,
      boolean overwrite,
      boolean isOldBlock,
      boolean wrongStore) {}

  /**
   * Reads the header+data region for a slot.
   *
   * <p>Returns a buffer sized {@code headerBlockLength + dataBlockLength + hdPadding} positioned at
   * the start (i.e., flipped). The caller consumes bytes to populate an {@code Entry}.
   *
   * @param offset slot index
   * @return a buffer containing the raw header+data bytes for the slot
   * @throws IOException on I/O errors
   */
  private ByteBuffer readHD(long offset) throws IOException {
    ByteBuffer buf = ByteBuffer.allocate(headerBlockLength + dataBlockLength + hdPadding);

    long pos = (headerBlockLength + dataBlockLength + hdPadding) * offset;
    do {
      int status = hdFC.read(buf, pos + buf.position());
      if (status == -1) throw new EOFException();
    } while (buf.hasRemaining());
    buf.flip();

    return buf;
  }

  /**
   * Returns a slot's flags, consulting the slot filter when available.
   *
   * <p>When the slot filter marks a slot as “checked”, its bits are translated to entry flags
   * without reading from the disk. Otherwise, the entry metadata is read. Note that {@code
   * ENTRY_FLAG_PLAINKEY} is not represented in the slot filter and is only visible when reading
   * metadata.
   *
   * @param offset slot index to read
   * @return entry flags at the slot
   * @throws IOException on I/O errors
   */
  private long getFlag(long offset) throws IOException {
    if ((!slotFilterDisabled) && USE_SLOT_FILTER) {
      int cache = slotFilter.get((int) offset);
      if ((cache & SLOT_CHECKED) != 0) {
        return translateSlotFlagsToEntryFlags(cache);
      }
    }
    Entry entry = readEntry(offset, null, null, false);
    Objects.requireNonNull(entry, "readEntry returned null for flag read");
    return entry.flag;
  }

  /**
   * Writes an entry to disk at a specific slot and updates the slot filter.
   *
   * <p>Preconditions: caller holds the necessary slot locks and the entry's {@code storeSize}
   * reflects the current store. The method encrypts the header/data, writes metadata and payload,
   * and sets {@code entry.curOffset}.
   *
   * @param entry entry to persist
   * @param digestedRoutingKey salted/digested key for computing the slot-filter prefix
   * @param offset slot index; must be less than {@link Integer#MAX_VALUE}
   * @throws IOException on I/O errors
   */
  private void writeEntry(Entry entry, byte[] digestedRoutingKey, long offset) throws IOException {
    if (offset >= Integer.MAX_VALUE) throw new IllegalArgumentException();

    if (!slotFilterDisabled)
      slotFilter.put((int) offset, entry.getSlotFilterEntry(digestedRoutingKey, entry.flag));

    cipherManager.encrypt(entry, random);

    ByteBuffer bf = entry.toMetaDataBuffer();
    do {
      int status = metaFC.write(bf, Entry.METADATA_LENGTH * offset + bf.position());
      if (status == -1) throw new EOFException();
    } while (bf.hasRemaining());

    bf = entry.toHDBuffer();
    if (bf != null) {
      long pos = (headerBlockLength + dataBlockLength + hdPadding) * offset;
      do {
        int status = hdFC.write(bf, pos + bf.position());
        if (status == -1) throw new EOFException();
      } while (bf.hasRemaining());
    }

    entry.curOffset = offset;
  }

  private void flushAndClose(boolean abort) {
    LOG.info("Flush and closing this store: {}", name);
    try {
      releaseLockQuietly(metaLock, "meta file");
      metaFC.force(true);
      metaFC.close();
    } catch (Exception e) {
      LOG.error("error flushing store metadata file", e);
    }
    try {
      releaseLockQuietly(hdLock, "data file");
      hdFC.force(true);
      hdFC.close();
    } catch (Exception e) {
      LOG.error("error flushing store data file", e);
    }
    if (!slotFilterDisabled) {
      if (!abort) slotFilter.shutdown();
      else slotFilter.abort();
    }
  }

  private void releaseLockQuietly(FileLock lock, String name) {
    if (lock == null || !lock.isValid()) return;
    try {
      lock.release();
    } catch (IOException e) {
      LOG.warn("Failed to release {} lock", name, e);
    }
  }

  /**
   * Enables or disables preallocation of the backing files to the target size during resizes.
   *
   * @param preallocate {@code true} to preallocate disk space; {@code false} to grow lazily
   */
  public void setPreallocate(boolean preallocate) {
    this.preallocate = preallocate;
  }

  /**
   * Grows or shrinks the metadata and data files to match a target number of entries.
   *
   * <p>Uses {@link Fallocate} to efficiently preallocate when enabled. Aligns the data file to
   * {@code headerBlockLength + dataBlockLength + hdPadding} and the metadata file to {@code
   * Entry.METADATA_LENGTH}.
   *
   * @param storeMaxEntries target number of entries (slots)
   */
  private void setStoreFileSize(long storeMaxEntries) {
    try {
      long oldMetaLen = metaRAF.length();
      long currentHdLen = hdRAF.length();

      final long newMetaLen = Entry.METADATA_LENGTH * storeMaxEntries;
      final long newHdLen = (headerBlockLength + dataBlockLength + hdPadding) * storeMaxEntries;

      if (preallocate) {
        try (WrapperKeepalive wrapperKeepalive = new WrapperKeepalive()) {
          wrapperKeepalive.start();
          if (oldMetaLen < newMetaLen) {
            // freenet-mobile-changed: Passing a file descriptor to avoid using reflection
            Fallocate.forChannel(metaFC, metaRAF.getFD(), newMetaLen)
                .fromOffset(oldMetaLen)
                .execute();
          }
          if (currentHdLen < newHdLen) {
            Fallocate.forChannel(hdFC, hdRAF.getFD(), newHdLen).fromOffset(currentHdLen).execute();
          }
        }
      }
      storeFileOffsetReady = 1 + storeMaxEntries;

      metaRAF.setLength(newMetaLen);
      hdRAF.setLength(newHdLen);
    } catch (IOException e) {
      LOG.error("error resizing store file", e);
    }
  }

  // ------------- Configuration
  /**
   * Configuration File
   *
   * <pre>
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *       |0|1|2|3|4|5|6|7|8|9|A|B|C|D|E|F|
   *  +----+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |0000|             Salt              |
   *  +----+---------------+---------------+
   *  |0010|   Store Size  | prevStoreSize |
   *  +----+---------------+-------+-------+
   *  |0020| Est Key Count |  Gen  | Flags |
   *  +----+-------+-------+-------+-------+
   *  |0030|   K   |      (reserved)       |
   *  +----+-------+-------+---------------+
   *  |0040|    writes     |     hits      |
   *  +----+---------------+---------------+
   *  |0050|    misses     | bloomFalsePos |
   *  +----+---------------+---------------+
   *
   *  Gen = Generation
   *    K = K for bloom filter
   * </pre>
   */
  private final File configFile;

  /**
   * Loads the store configuration, creating a new one when missing.
   *
   * <p>Initializes the cipher manager from the stored salt (optionally protected by {@code
   * masterKey}). When the config file does not exist, a new salt is generated and persisted.
   *
   * @param masterKey optional master key used to encrypt/decrypt the on-disk salt
   * @return {@code true} if a new configuration was created; {@code false} when an existing one was
   *     loaded
   */
  private boolean loadConfigFile(byte[] masterKey) throws IOException {
    assert cipherManager == null; // never load the configuration twice

    if (!configFile.exists()) {
      return createNewConfig(masterKey);
    } else {
      return loadExistingConfig(masterKey);
    }
  }

  private boolean createNewConfig(byte[] masterKey) {
    byte[] newsalt = new byte[0x10];
    random.nextBytes(newsalt);
    byte[] diskSalt = newsalt;
    if (masterKey != null) {
      BlockCipher cipher = newRijndael();
      cipher.initialize(masterKey);
      diskSalt = new byte[0x10];
      cipher.encipher(newsalt, diskSalt);
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Encrypting with {}" + STR_FROM + "{}",
            HexUtil.bytesToHex(newsalt),
            HexUtil.bytesToHex(diskSalt));
    }
    cipherManager = new CipherManager(newsalt, diskSalt);
    writeConfigFile();
    return true;
  }

  private boolean loadExistingConfig(byte[] masterKey) throws IOException {
    try (RandomAccessFile raf = new RandomAccessFile(configFile, "r")) {
      byte[] salt = new byte[0x10];
      raf.readFully(salt);

      byte[] diskSalt = salt;
      if (masterKey != null) {
        BlockCipher cipher = newRijndael();
        cipher.initialize(masterKey);
        salt = new byte[0x10];
        cipher.decipher(diskSalt, salt);
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Encrypting (new) with {}" + STR_FROM + "{}",
              HexUtil.bytesToHex(salt),
              HexUtil.bytesToHex(diskSalt));
      }

      cipherManager = new CipherManager(salt, diskSalt);

      storeSize = raf.readLong();
      if (storeSize <= 0) throw new IOException("Bogus datastore size");
      prevStoreSize = raf.readLong();
      keyCount.set(raf.readLong());
      generation = raf.readInt();
      flags = raf.readInt();

      if (((flags & FLAG_DIRTY) != 0)
          &&
          // Note: When slot-filter persistence is enabled, we conservatively request a rebuild.
          ResizablePersistentIntBuffer.getPersistenceTime() != -1) flags |= FLAG_REBUILD_BLOOM;

      readOptionalTrailingCounters(raf);

      return false;
    } catch (IOException e) {
      // Corrupted? Delete it and try again. Do not log-and-throw; rethrow with context if
      // unrecoverable.
      if (deleteCorruptedConfigAndMeta()) {
        return loadConfigFile(masterKey);
      }
      throw new IOException(
          "Failed to load config for store '"
              + name
              + "' ("
              + configFile
              + ") — file appears corrupt and could not be deleted; "
              + "please delete the store manually.",
          e);
    }
  }

  /** Reads optional trailing counters from the config file; tolerates EOF for compatibility. */
  private void readOptionalTrailingCounters(RandomAccessFile raf) throws IOException {
    try {
      raf.readInt(); // bloomFilterK
      raf.readInt(); // reserved
      raf.readLong(); // reserved
      long w = raf.readLong();
      writes.set(w);
      initialWrites = w;
      LOG.info("Set writes to saved value {}", w);
      hits.set(raf.readLong());
      initialHits = hits.get();
      misses.set(raf.readLong());
      initialMisses = misses.get();
      bloomFalsePos.set(raf.readLong());
      initialBloomFalsePos = bloomFalsePos.get();
    } catch (EOFException _) {
      // Ignore, back compatibility.
    }
  }

  private BlockCipher newRijndael() {
    try {
      return new Rijndael(256, 128);
    } catch (UnsupportedCipherException e) {
      throw new IllegalStateException("Impossible: no Rijndael(256,128): " + e, e);
    }
  }

  /**
   * Writes the configuration file atomically.
   *
   * <p>Serializes salts, sizing, generation, flags, and counters to a temporary file and then moves
   * it into place. Guarded by {@link #configLock}.
   */
  private void writeConfigFile() {
    configLock.writeLock().lock();
    try {

      File tempConfig = new File(configFile.getPath() + ".tmp");
      try (RandomAccessFile raf = new RandomAccessFile(tempConfig, "rw")) {
        raf.seek(0);
        raf.write(cipherManager.getDiskSalt());

        raf.writeLong(storeSize);
        raf.writeLong(prevStoreSize);
        raf.writeLong(keyCount.get());
        raf.writeInt(generation);
        raf.writeInt(flags);
        raf.writeInt(0); // bloomFilterK
        raf.writeInt(0);
        raf.writeLong(0);
        raf.writeLong(writes.get());
        raf.writeLong(hits.get());
        raf.writeLong(misses.get());
        raf.writeLong(bloomFalsePos.get());

        raf.getFD().sync();
      }

      FileUtil.moveTo(tempConfig, configFile);
    } catch (IOException ioe) {
      LOG.error("error writing config file for {}", name, ioe);
    } finally {
      configLock.writeLock().unlock();
    }
  }

  // ------------- Store resizing
  private long prevStoreSize = 0;
  private final Lock cleanerLock = new ReentrantLock(); // local to this datastore
  private final Condition cleanerCondition = cleanerLock.newCondition();
  private static final Lock cleanerGlobalLock = new ReentrantLock(); // global across all datastore
  private final Cleaner cleanerThread;
  private final CleanerStatusUserAlert cleanerStatusUserAlert;

  private final Entry notModified = new Entry();

  private interface BatchProcessor<T extends StorableBlock> {
    // initialize
    void init();

    // call this after reading RESIZE_MEMORY_ENTRIES entries
    // return false to abort
    boolean batch(long entriesLeft);

    // call this on abort (e.g., node shutdown)
    void abort();

    void finish();

    // return <code>null</code> to free the entry
    // return notModified to keep the old entry
    SaltedHashFreenetStore<T>.Entry process(SaltedHashFreenetStore<T>.Entry entry);

    /** Does this batch processor want to see free entries? */
    boolean wantFreeEntries();
  }

  private class Cleaner extends NativeThread {
    /** How often the clean should run */
    private static final int CLEANER_PERIOD = 5 * 60 * 1000; // 5 minutes

    private volatile boolean isRebuilding;
    private volatile boolean isResizing;

    public Cleaner() {
      super("Store-" + name + "-Cleaner", NativeThread.PriorityLevel.LOW_PRIORITY.value, false);
      setPriority(NativeThread.PriorityLevel.MIN_PRIORITY.value);
      setDaemon(true);
    }

    @Override
    public void realRun() {

      if (!noCleanerSleep) {
        try {
          int sleepMillis = (CLEANER_PERIOD / 2) + random.nextInt(CLEANER_PERIOD + 1);
          Thread.sleep(sleepMillis);
        } catch (InterruptedException _) {
          Thread.currentThread().interrupt();
          return;
        }
      }

      if (shutdown) return;

      while (!shutdown) {
        runCleanerIteration();
      }
    }

    private void runCleanerIteration() {
      cleanerLock.lock();
      try {
        long prevSize;
        configLock.readLock().lock();
        try {
          prevSize = prevStoreSize;
        } finally {
          configLock.readLock().unlock();
        }

        if (prevSize != 0 && cleanerGlobalLock.tryLock()) {
          try {
            isResizing = true;
            resizeStore(prevSize, true);
          } finally {
            isResizing = false;
            cleanerGlobalLock.unlock();
          }
        }

        boolean rebuildBloomRequested;
        configLock.readLock().lock();
        try {
          rebuildBloomRequested = ((flags & FLAG_REBUILD_BLOOM) != 0);
        } finally {
          configLock.readLock().unlock();
        }
        if (rebuildBloomRequested && prevStoreSize == 0 && cleanerGlobalLock.tryLock()) {
          try {
            isRebuilding = true;
            rebuildBloom();
          } finally {
            isRebuilding = false;
            cleanerGlobalLock.unlock();
          }
        }

        writeConfigFile();

        try {
          long deadline = System.currentTimeMillis() + CLEANER_PERIOD;
          while (!shutdown) {
            long remaining = deadline - System.currentTimeMillis();
            if (remaining <= 0) break;
            boolean awaited = cleanerCondition.await(remaining, TimeUnit.MILLISECONDS);
            if (!awaited && LOG.isTraceEnabled()) LOG.trace("Cleaner await timed out");
          }
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          LOG.trace("interrupted", e);
        }
      } finally {
        cleanerLock.unlock();
      }
    }

    private static final int RESIZE_MEMORY_ENTRIES =
        128; // temporary memory store size (in # of entries)

    /** Move old entries to new location and resize store */
    private void resizeStore(final long _prevStoreSize, final boolean sleep) {
      LOG.info("Starting datastore resize for {}", name);

      BatchProcessor<T> resizeProcesser = createResizeProcessor(_prevStoreSize);

      batchProcessEntries(resizeProcesser, _prevStoreSize, true, sleep);
    }

    private BatchProcessor<T> createResizeProcessor(final long _prevStoreSize) {
      return new ResizeProcessor(_prevStoreSize);
    }

    private final class ResizeProcessor implements BatchProcessor<T> {
      private final long previousStoreSize;
      private final Deque<Entry> oldEntryList = new LinkedList<>();
      private int i = 0;

      ResizeProcessor(long previousStoreSize) {
        this.previousStoreSize = previousStoreSize;
      }

      @Override
      public void init() {
        if (storeSize > previousStoreSize) {
          setStoreFileSize(storeSize);
        }

        configLock.writeLock().lock();
        try {
          generation++;
          keyCount.set(0);
        } finally {
          configLock.writeLock().unlock();
        }

        WrapperManager.signalStarting(
            (int) (RESIZE_MEMORY_ENTRIES * SECONDS.toMillis(30) + SECONDS.toMillis(1)));
      }

      @Override
      public Entry process(Entry entry) {
        int oldGeneration = entry.generation;
        if (oldGeneration != generation) {
          entry.generation = generation;
          keyCount.incrementAndGet();
        }

        if (entry.storeSize == storeSize) {
          // new size, don't have to relocate
          if (entry.generation != generation) {
            return entry;
          } else {
            return notModified;
          }
        }

        // remove from the store, prepare for relocation
        if (oldGeneration == generation) {
          // should be impossible
          LOG.atError()
              .addArgument(HexUtil.bytesToHex(entry.getDigestedRoutingKey()))
              .addArgument(entry.curOffset)
              .log("new generation object with wrong storeSize. DigestedRoutingKey={}, Offset={}");
        }
        try {
          entry.setHD(readHD(entry.curOffset));
          oldEntryList.add(entry);
          if (oldEntryList.size() > RESIZE_MEMORY_ENTRIES) {
            oldEntryList.poll();
          }
        } catch (IOException e) {
          LOG.error("error reading entry (offset={})", entry.curOffset, e);
        }
        return null;
      }

      @Override
      public boolean batch(long entriesLeft) {
        WrapperManager.signalStarting(
            (int) (RESIZE_MEMORY_ENTRIES * SECONDS.toMillis(30) + SECONDS.toMillis(1)));

        if (i++ % 16 == 0) {
          writeConfigFile();
        }

        // shrink data file to the current size
        if (storeSize < previousStoreSize) {
          setStoreFileSize(Math.max(storeSize, entriesLeft));
        }

        // try to resolve the list
        oldEntryList.removeIf(this::resolveOldEntry);

        return previousStoreSize == prevStoreSize;
      }

      @Override
      public void abort() {
        // Do nothing
      }

      @Override
      public void finish() {
        configLock.writeLock().lock();
        try {
          if (previousStoreSize != prevStoreSize) {
            return;
          }
          prevStoreSize = 0;
          if (!slotFilterDisabled && slotFilter != null) {
            if (slotFilter.size() != (int) storeSize) {
              slotFilter.resize((int) storeSize);
            } else {
              slotFilter.forceWrite();
            }
          }

          flags &= ~FLAG_REBUILD_BLOOM;
          resizeCompleteCondition.signalAll();
        } finally {
          configLock.writeLock().unlock();
        }

        LOG.info("Finish resizing ({})", name);
      }

      public boolean wantFreeEntries() {
        return false;
      }

      // Helpers used only by ResizeProcessor
      private boolean isFree(long offset) throws IOException {
        if ((!slotFilterDisabled) && slotFilter != null && USE_SLOT_FILTER) {
          int cache = slotFilter.get((int) offset);
          if ((cache & SLOT_CHECKED) != 0) {
            return slotCacheIsFree(cache);
          }
        }
        Entry entry = readEntry(offset, null, null, false);
        Objects.requireNonNull(entry, "readEntry returned null for isFree");
        return entry.isFree();
      }

      private byte[] getDigestedKeyFromOffset(long offset) throws IOException {
        Entry entry = readEntry(offset, null, null, false);
        Objects.requireNonNull(entry, "readEntry returned null for digestedKey");
        return entry.getDigestedRoutingKey();
      }

      private boolean resolveOldEntry(Entry entry) {
        Map<Long, Condition> lockMap = lockDigestedKey(entry.getDigestedRoutingKey(), false);
        if (lockMap.isEmpty()) return false;
        try {
          entry.storeSize = storeSize;
          long[] offsets = entry.getOffset();

          // Check for occupied entry with the same key
          for (long offset : offsets) {
            try {
              if (!isFree(offset)
                  && Arrays.equals(
                      getDigestedKeyFromOffset(offset), entry.getDigestedRoutingKey())) {
                // do nothing
                return true;
              }
            } catch (IOException e) {
              LOG.trace("IOException while checking existing entry in resolveOldEntry", e);
            }
          }

          // Check for free entry
          for (long offset : offsets) {
            try {
              if (isFree(offset)) {
                byte[] digestedKey = entry.getDigestedRoutingKey();
                writeEntry(entry, digestedKey, offset);
                keyCount.incrementAndGet();
                return true;
              }
            } catch (IOException e) {
              LOG.trace("IOException while looking for free slot in resolveOldEntry", e);
            }
          }
          return false;
        } finally {
          unlockDigestedKey(entry.getDigestedRoutingKey(), false, lockMap);
        }
      }
    }

    /** Rebuild bloom filter */
    private void rebuildBloom() {
      if (slotFilterDisabled) return;
      LOG.info("Start rebuilding slot filter ({})", name);

      BatchProcessor<T> rebuildBloomProcessor = new RebuildBloomProcessor();

      // In regular cleaner iterations, we do not sleep between batches.
      batchProcessEntries(rebuildBloomProcessor, storeSize, false, false);
    }

    private final class RebuildBloomProcessor implements BatchProcessor<T> {
      int i = 0;

      @Override
      public void init() {
        configLock.writeLock().lock();
        try {
          keyCount.set(0);
        } finally {
          configLock.writeLock().unlock();
        }

        WrapperManager.signalStarting(
            (int) (RESIZE_MEMORY_ENTRIES * SECONDS.toMillis(5) + SECONDS.toMillis(1)));
      }

      @Override
      public Entry process(Entry entry) {
        if (!slotFilterDisabled && slotFilter != null) {
          int cache = entry.getSlotFilterEntry();
          try {
            slotFilter.put((int) entry.curOffset, cache, true);
          } catch (IOException e) {
            LOG.error("Unable to update slot filter in bloom rebuild: {}", e, e);
          }
        }
        if (!entry.isFree()) {
          keyCount.incrementAndGet();

          if (entry.generation != generation) {
            entry.generation = generation;
            return entry;
          }
        }
        return notModified;
      }

      @Override
      public boolean batch(long entriesLeft) {
        WrapperManager.signalStarting(
            (int) (RESIZE_MEMORY_ENTRIES * SECONDS.toMillis(5) + SECONDS.toMillis(1)));

        if (i++ % 16 == 0) {
          writeConfigFile();
        }
        if (i++ % 1024 == 0 && !slotFilterDisabled && slotFilter != null) {
          slotFilter.forceWrite();
        }

        return prevStoreSize == 0;
      }

      @Override
      public void abort() {
        // Do nothing
      }

      @Override
      public void finish() {
        if (!slotFilterDisabled && slotFilter != null) {
          slotFilter.forceWrite();
        }
        configLock.writeLock().lock();
        try {
          flags &= ~FLAG_REBUILD_BLOOM;
          writeConfigFile();
        } finally {
          configLock.writeLock().unlock();
        }
        LOG.info("{} cleaner finished successfully.", name);
        LOG.info("Finish rebuilding bloom filter ({})", name);
      }

      public boolean wantFreeEntries() {
        return true;
      }
    }

    private volatile long entriesLeft;
    private volatile long entriesTotal;

    private void batchProcessEntries(
        BatchProcessor<T> processor, long storeSize, boolean reverse, boolean sleep) {

      entriesLeft = entriesTotal = storeSize;

      long startOffset;
      long step;
      if (!reverse) {
        startOffset = 0;
        step = RESIZE_MEMORY_ENTRIES;
      } else {
        startOffset = ((storeSize - 1) / RESIZE_MEMORY_ENTRIES) * RESIZE_MEMORY_ENTRIES;
        step = -RESIZE_MEMORY_ENTRIES;
      }

      int i = 0;
      processor.init();
      try {
        for (long curOffset = startOffset;
            curOffset >= 0 && curOffset < storeSize;
            curOffset += step) {
          if (abortIfShuttingDown(processor)) return;

          if (i++ % 64 == 0) printCleanerProgress();

          if (!processBatchWindow(curOffset, storeSize, reverse, processor)) return;

          if (!sleepAfterBatch(sleep, processor)) return;
        }
        processor.finish();
      } catch (Exception e) {
        LOG.error("Caught: {} while shrinking", e, e);
        processor.abort();
      }
    }

    private boolean abortIfShuttingDown(BatchProcessor<T> processor) {
      if (shutdown) {
        processor.abort();
        return true;
      }
      return false;
    }

    private void printCleanerProgress() {
      LOG.info("{} cleaner in progress: {}/{}", name, (entriesTotal - entriesLeft), entriesTotal);
    }

    private boolean processBatchWindow(
        long curOffset, long storeSize, boolean reverse, BatchProcessor<T> processor) {
      boolean ok = batchProcessEntries(curOffset, processor);
      if (!ok) {
        processor.abort();
        return false;
      }
      entriesLeft =
          reverse ? curOffset : Math.max(storeSize - curOffset - RESIZE_MEMORY_ENTRIES, 0);
      if (!processor.batch(entriesLeft)) {
        processor.abort();
        return false;
      }
      return true;
    }

    private boolean sleepAfterBatch(boolean sleep, BatchProcessor<T> processor) {
      try {
        if (sleep) Thread.sleep(100);
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
        processor.abort();
        return false;
      }
      return true;
    }

    // (moved helpers isFree(...) and getDigestedKeyFromOffset(...) into ResizeProcessor)

    /**
     * Processes a fixed-size window of entries starting at {@code offset}.
     *
     * <p>Acquires per-entry locks for a window of {@code RESIZE_MEMORY_ENTRIES} entries, reads the
     * metadata into a buffer, lets the processor decide on modifications, and writes back if
     * needed. Returns {@code false} when locking fails or shutdown is requested.
     *
     * @param offset start slot index for the window
     * @param processor batch processor
     * @return {@code true} on success; {@code false} if processing was aborted
     */
    private boolean batchProcessEntries(long offset, BatchProcessor<T> processor) {
      final int length = RESIZE_MEMORY_ENTRIES;
      boolean wantFreeEntries = processor.wantFreeEntries();
      Condition[] locked = new Condition[length];
      try {
        if (!acquireRegionLocks(locked, offset)) return false;

        long startFileOffset = offset * Entry.METADATA_LENGTH;
        long bufLen = Entry.METADATA_LENGTH * (long) length;
        ByteBuffer buf = ByteBuffer.allocate((int) bufLen);

        readRegionBuffer(startFileOffset, buf);
        buf.flip();

        boolean dirty = processBufferAndMark(buf, offset, processor, wantFreeEntries);
        writeBackIfDirty(startFileOffset, buf, dirty);
        return true;
      } finally {
        // unlock
        for (int i = 0; i < locked.length; i++)
          if (locked[i] != null) lockManager.unlockEntry(offset + i, locked[i]);
      }
    }

    private boolean acquireRegionLocks(Condition[] locked, long offset) {
      for (int i = 0; i < locked.length; i++) {
        locked[i] = lockManager.lockEntry(offset + i);
        if (locked[i] == null) return false;
      }
      return true;
    }

    private void readRegionBuffer(long startFileOffset, ByteBuffer buf) {
      try {
        while (buf.hasRemaining()) {
          int status = metaFC.read(buf, startFileOffset + buf.position());
          if (status == -1) break;
        }
      } catch (IOException ioe) {
        if (shutdown) return;
        LOG.error("unexpected IOException while reading batch metadata", ioe);
      }
    }

    private boolean processBufferAndMark(
        ByteBuffer buf, long offset, BatchProcessor<T> processor, boolean wantFreeEntries) {
      boolean dirty = false;
      int limitEntries = buf.limit() / Entry.METADATA_LENGTH;
      for (int j = 0; !shutdown && j < limitEntries; j++) {
        buf.position(j * Entry.METADATA_LENGTH);

        ByteBuffer enBuf = buf.slice();
        enBuf.limit(Entry.METADATA_LENGTH);

        Entry entry = new Entry(enBuf, null);
        entry.curOffset = offset + j;

        if (!(entry.isFree() && !wantFreeEntries)) {
          Entry newEntry = processor.process(entry);
          if (newEntry == null) {
            dirty |= handleFreeEntry(buf, offset, j);
          } else if (newEntry != notModified) {
            dirty |= handleModifiedEntry(buf, offset, j, newEntry);
          } // else: no changes
        }
      }
      return dirty;
    }

    private boolean handleFreeEntry(ByteBuffer buf, long offset, int j) {
      buf.position(j * Entry.METADATA_LENGTH);
      buf.put(ByteBuffer.allocate(Entry.METADATA_LENGTH));
      keyCount.decrementAndGet();
      if (!slotFilterDisabled) {
        try {
          slotFilter.put((int) (offset + j), SLOT_CHECKED);
        } catch (IOException e) {
          LOG.error("Slot filter update failed for freed entry: {}", e, e);
        }
      }
      return true;
    }

    private boolean handleModifiedEntry(ByteBuffer buf, long offset, int j, Entry newEntry) {
      buf.position(j * Entry.METADATA_LENGTH);
      buf.put(newEntry.toMetaDataBuffer());

      assert newEntry.header == null; // not supported
      assert newEntry.data == null; // not supported

      if (!slotFilterDisabled) {
        int newVal = newEntry.getSlotFilterEntry();
        if (slotFilter.get((int) (offset + j)) != newVal) {
          try {
            slotFilter.put((int) (offset + j), newVal);
          } catch (IOException e) {
            LOG.error("Slot filter update failed for modified entry: {}", e, e);
          }
        }
      }
      return true;
    }

    private void writeBackIfDirty(long startFileOffset, ByteBuffer buf, boolean dirty) {
      if (!dirty) return;
      buf.flip();
      try {
        while (buf.hasRemaining()) {
          metaFC.write(buf, startFileOffset + buf.position());
        }
      } catch (IOException ioe) {
        LOG.error("unexpected IOException while writing batch metadata", ioe);
      }
    }
  }

  private final class CleanerStatusUserAlert extends AbstractUserAlert {
    private final Cleaner cleaner;

    private CleanerStatusUserAlert(Cleaner cleaner) {
      this.cleaner = cleaner;
    }

    @Override
    public String anchor() {
      return "store-cleaner-" + name;
    }

    @Override
    public String dismissButtonText() {
      return NodeL10n.getBase().getString("UserAlert.hide");
    }

    @Override
    public HTMLNode getHTMLText() {
      return new HTMLNode("#", getText());
    }

    @Override
    public short getPriorityClass() {
      return UserAlert.ERROR; // So everyone sees it.
    }

    @Override
    public String getShortText() {
      if (cleaner.isResizing)
        return NodeL10n.getBase()
            .getString(
                "SaltedHashCryptaStore.shortResizeProgress", //
                new String[] {"name", KEY_PROCESSED, KEY_TOTAL}, //
                new String[] {
                  name,
                  String.valueOf(cleaner.entriesTotal - cleaner.entriesLeft),
                  String.valueOf(cleaner.entriesTotal)
                });
      else
        return NodeL10n.getBase()
            .getString(
                "SaltedHashCryptaStore.shortRebuildProgress"
                    + ((slotFilter != null && slotFilter.isNew()) ? "New" : ""),
                new String[] {"name", KEY_PROCESSED, KEY_TOTAL}, //
                new String[] {
                  name,
                  String.valueOf(cleaner.entriesTotal - cleaner.entriesLeft),
                  String.valueOf(cleaner.entriesTotal)
                });
    }

    @Override
    public String getText() {
      if (cleaner.isResizing)
        return NodeL10n.getBase()
            .getString(
                "SaltedHashCryptaStore.longResizeProgress", //
                new String[] {"name", KEY_PROCESSED, KEY_TOTAL}, //
                new String[] {
                  name,
                  String.valueOf(cleaner.entriesTotal - cleaner.entriesLeft),
                  String.valueOf(cleaner.entriesTotal)
                });
      else
        return NodeL10n.getBase()
            .getString(
                "SaltedHashCryptaStore.longRebuildProgress"
                    + ((slotFilter != null && slotFilter.isNew()) ? "New" : ""),
                new String[] {"name", KEY_PROCESSED, KEY_TOTAL},
                new String[] {
                  name,
                  String.valueOf(cleaner.entriesTotal - cleaner.entriesLeft),
                  String.valueOf(cleaner.entriesTotal)
                });
    }

    @Override
    public String getTitle() {
      return NodeL10n.getBase()
          .getString(
              "SaltedHashCryptaStore.cleanerAlertTitle", //
              new String[] {"name"}, //
              new String[] {name});
    }

    @Override
    public boolean isValid() {
      return cleaner.isRebuilding || cleaner.isResizing;
    }

    @Override
    public void isValid(boolean validity) {
      // Ignore
    }

    @Override
    public void onDismiss() {
      // Ignore
    }

    @Override
    public boolean shouldUnregisterOnDismiss() {
      return true;
    }

    @Override
    public boolean userCanDismiss() {
      return false;
    }
  }

  /**
   * Registers the cleaner status alert with the provided manager so progress appears in the UI.
   *
   * @param userAlertManager destination manager; must not be {@code null}
   */
  public void setUserAlertManager(UserAlertManager userAlertManager) {
    if (cleanerStatusUserAlert != null) userAlertManager.register(cleanerStatusUserAlert);
  }

  /**
   * Requests the store be resized to a new capacity.
   *
   * <p>When {@code shrinkNow} is {@code false}, the cleaner performs the work asynchronously. When
   * {@code shrinkNow} is {@code true}, the method attempts to complete the resize inline when it
   * can acquire the global cleaner lock; otherwise it waits for the cleaner to finish. The slot
   * filter is resized to the larger of old/new sizes to preserve information during migration.
   *
   * @param newStoreSize desired number of slots; must be ≤ {@link Integer#MAX_VALUE}
   * @param shrinkNow whether to complete the resize synchronously when possible
   * @throws IllegalArgumentException when {@code newStoreSize} exceeds the supported maximum
   */
  @Override
  public void setMaxKeys(long newStoreSize, boolean shrinkNow) {
    LOG.info("[{}] Resize newStoreSize={}, shinkNow={}", name, newStoreSize, shrinkNow);

    if (newStoreSize > Integer.MAX_VALUE) { // 32-bit limit due to ResizablePersistentIntBuffer.
      throw new IllegalArgumentException(
          "Store size over MAXINT not supported due to ResizablePersistentIntBuffer limitations.");
    }

    configLock.writeLock().lock();
    long old;
    try {
      if (newStoreSize == this.storeSize) return;

      if (prevStoreSize != 0) {
        LOG.info("[{}] resize already in progress, ignore resize request", name);
        return;
      }

      old = storeSize;
      prevStoreSize = storeSize;
      storeSize = newStoreSize;
      if (!slotFilterDisabled) slotFilter.resize((int) Math.max(storeSize, prevStoreSize));
      writeConfigFile();
    } finally {
      configLock.writeLock().unlock();
    }

    if (cleanerLock.tryLock()) {
      cleanerCondition.signal();
      cleanerLock.unlock();
    }

    if (shrinkNow) {
      boolean resizedInline = false;
      // If possible, complete the resize synchronously. This covers tests that mock the Ticker
      // and therefore never start the cleaner thread.
      if (cleanerGlobalLock.tryLock()) {
        try {
          cleanerThread.resizeStore(old, /*sleep*/ false);
          resizedInline = true;
        } finally {
          cleanerGlobalLock.unlock();
        }
      }

      if (!resizedInline) {
        configLock.writeLock().lock();
        try {
          LOG.info("Waiting for resize to complete...");
          while (prevStoreSize == old) {
            resizeCompleteCondition.awaitUninterruptibly();
          }
          LOG.info(
              "Completed shrink, old size was {} new size was {} size is now {} (prev={})",
              old,
              newStoreSize,
              storeSize,
              prevStoreSize);
        } finally {
          configLock.writeLock().unlock();
        }
      } else {
        // Inline path already finished and updated state.
        LOG.info(
            "Completed shrink synchronously, old size was {} new size was {} size is now {}",
            old,
            newStoreSize,
            storeSize);
      }
    }
  }

  // ------------- Locking
  volatile boolean shutdown = false;
  private final LockManager lockManager;
  private final ReadWriteLock configLock = new ReentrantReadWriteLock();
  private final Condition resizeCompleteCondition = configLock.writeLock().newCondition();

  /**
   * Acquires entry locks for all candidate slot offsets of the given digested key.
   *
   * <p>Offsets are computed for the current store size and, when {@code usePrevStoreSize} is {@code
   * true} and a resize is in progress, also for {@code prevStoreSize}. Offsets are sorted and
   * locked in ascending order to avoid deadlocks. If any lock cannot be acquired (e.g., another
   * thread holds it or the store is shutting down), all already-acquired locks are released and an
   * empty map is returned.
   *
   * <p>The caller must release the returned locks by calling {@link #unlockDigestedKey(byte[],
   * boolean, Map)} with the exact map returned by this method.
   *
   * @param digestedKey salted/digested routing key
   * @param usePrevStoreSize whether to include offsets computed against {@code prevStoreSize} to
   *     cover in‑progress resizes
   * @return a map of {@code offset → Condition} for each acquired lock; empty when acquisition did
   *     not get all required locks
   */
  private Map<Long, Condition> lockDigestedKey(byte[] digestedKey, boolean usePrevStoreSize) {
    // use a set to prevent duplicated offsets,
    // a sorted set to prevent deadlocks
    SortedSet<Long> offsets = new TreeSet<>();
    long[] offsetArray = getOffsetFromDigestedKey(digestedKey, storeSize);
    for (long offset : offsetArray) offsets.add(offset);
    if (usePrevStoreSize && prevStoreSize != 0) {
      offsetArray = getOffsetFromDigestedKey(digestedKey, prevStoreSize);
      for (long offset : offsetArray) offsets.add(offset);
    }

    Map<Long, Condition> locked = new TreeMap<>();
    for (long offset : offsets) {
      Condition condition = lockManager.lockEntry(offset);
      if (condition == null) break;
      locked.put(offset, condition);
    }

    if (locked.size() == offsets.size()) {
      return locked;
    } else {
      // failed, remove the locks
      for (Map.Entry<Long, Condition> e : locked.entrySet())
        lockManager.unlockEntry(e.getKey(), e.getValue());
      return java.util.Collections.emptyMap();
    }
  }

  private void unlockDigestedKey(
      byte[] digestedKey, boolean usePrevStoreSize, Map<Long, Condition> lockMap) {
    // use a set to prevent duplicated offsets
    SortedSet<Long> offsets = new TreeSet<>();
    long[] offsetArray = getOffsetFromDigestedKey(digestedKey, storeSize);
    for (long offset : offsetArray) offsets.add(offset);
    if (usePrevStoreSize && prevStoreSize != 0) {
      offsetArray = getOffsetFromDigestedKey(digestedKey, prevStoreSize);
      for (long offset : offsetArray) offsets.add(offset);
    }

    for (long offset : offsets) {
      lockManager.unlockEntry(offset, lockMap.get(offset));
      lockMap.remove(offset);
    }
  }

  /** Runnable that closes the store during an application shutdown. */
  public class ShutdownDB implements Runnable {
    @Override
    public void run() {
      close();
    }
  }

  // ------------- Hashing
  private CipherManager cipherManager;

  // Plain-key mapping is implemented via CipherManager; see getOffsetFromDigestedKey() for details
  /**
   * Closes the store with a clean shutdown. Equivalent to {@link #close(boolean)} with {@code
   * false}.
   */
  public void close() {
    close(false);
  }

  /**
   * Closes the store gracefully.
   *
   * <p>Stops the cleaner, flushes and closes files, clears the dirty flag, and writes the config
   * file. Safe to call more than once.
   */
  public void close(boolean abort) {
    if (closeCalled.compareAndSet(false, true)) {
      shutdown = true;
      lockManager.shutdown();

      cleanerLock.lock();
      try {
        cleanerCondition.signalAll();
        cleanerThread.interrupt();
      } finally {
        cleanerLock.unlock();
      }

      configLock.writeLock().lock();
      try {
        flushAndClose(abort);
        flags &= ~FLAG_DIRTY; // clean shutdown
        writeConfigFile();
      } finally {
        configLock.writeLock().unlock();
      }
      cipherManager.shutdown();
      LOG.info("Successfully closed store: {}", name);
    } else {
      LOG.info("Store already closed: {}", name);
    }
  }

  /**
   * Computes candidate slot offsets for a digested routing key using quadratic probing.
   *
   * @param digestedKey salted/digested routing key
   * @param storeSize current number of slots
   * @return up to {@link #OPTION_MAX_PROBE} unique offsets in probe order
   */
  private long[] getOffsetFromDigestedKey(byte[] digestedKey, long storeSize) {
    long keyValue = Fields.bytesToLong(digestedKey);
    long[] offsets = new long[OPTION_MAX_PROBE];

    for (int i = 0; i < OPTION_MAX_PROBE; i++) {
      // h + 141 i^2 + 13 i
      offsets[i] = ((keyValue + 141 * (i * i) + 13 * i) & Long.MAX_VALUE) % storeSize;
      // Make sure the slots are all unique.
      // Important for very small stores e.g., in unit tests.
      while (true) {
        boolean clear = true;
        for (int j = 0; j < i; j++) {
          if (offsets[i] == offsets[j]) {
            offsets[i] = (offsets[i] + 1) % storeSize;
            clear = false;
          }
        }
        if (clear || OPTION_MAX_PROBE > storeSize) break;
      }
    }

    return offsets;
  }

  // ------------- Statistics (a.k.a. lies)
  private final AtomicLong hits = new AtomicLong();
  private final AtomicLong misses = new AtomicLong();
  private final AtomicLong writes = new AtomicLong();
  private final AtomicLong keyCount = new AtomicLong();
  private final AtomicLong bloomFalsePos = new AtomicLong();

  private long initialHits;
  private long initialMisses;
  private long initialWrites;
  private long initialBloomFalsePos;

  /** Total number of successful lookups since counters were last reset/persisted. */
  @Override
  public long hits() {
    return hits.get();
  }

  /** Total number of misses since counters were last reset/persisted. */
  @Override
  public long misses() {
    return misses.get();
  }

  /** Total number of writes since counters were last reset/persisted. */
  @Override
  public long writes() {
    return writes.get();
  }

  /** Current number of keys known in the store (the best effort during resizes). */
  @Override
  public long keyCount() {
    return keyCount.get();
  }

  /** Configured maximum number of slots in the current generation. */
  @Override
  public long getMaxKeys() {
    configLock.readLock().lock();
    long storeSizeLocal = storeSize;
    configLock.readLock().unlock();
    return storeSizeLocal;
  }

  /** Number of false positives reported by the slot filter (historically “bloom”). */
  @Override
  public long getBloomFalsePositive() {
    return bloomFalsePos.get();
  }

  /**
   * Returns whether a key is probably present based on the slot filter only.
   *
   * <p>Used to avoid I/O when the filter indicates a definite non-match. Returns {@code true} when
   * any candidate slot is a likely match or when insufficient information is available (unknown
   * slots), {@code false} only when all checked slots definitively do not match.
   */
  @Override
  public boolean probablyInStore(byte[] routingKey) {
    configLock.readLock().lock();

    try {
      if (slotFilterDisabled) return true;

      byte[] digestedKey = cipherManager.getDigestedKey(routingKey);
      long[] offsets = getOffsetFromDigestedKey(digestedKey, storeSize);

      boolean anyNotValid = false;

      MatchCheck mc1 = checkOffsetsLikelyMatch(digestedKey, offsets);
      if (mc1.found()) return true;
      anyNotValid |= mc1.anyNotValid();

      if (prevStoreSize != 0) {
        long[] prevOffsets = getOffsetFromDigestedKey(digestedKey, prevStoreSize);
        MatchCheck mc2 = checkOffsetsLikelyMatch(digestedKey, prevOffsets);
        if (mc2.found()) return true;
        anyNotValid |= mc2.anyNotValid();
      }

      return anyNotValid;
    } finally {
      configLock.readLock().unlock();
    }
  }

  private record MatchCheck(boolean found, boolean anyNotValid) {}

  private MatchCheck checkOffsetsLikelyMatch(byte[] digestedKey, long[] offsets) {
    boolean anyNotValid = false;
    for (long offset : offsets) {
      if (offset > Integer.MAX_VALUE)
        return new MatchCheck(true, anyNotValid); // overflow guard for 32-bit index
      int cache = slotFilter.get((int) offset);
      boolean validCache = (cache & SLOT_CHECKED) != 0;
      if (!validCache) {
        anyNotValid = true;
        continue;
      }
      boolean likelyMatch = slotCacheLikelyMatch(cache, digestedKey);
      if (likelyMatch) return new MatchCheck(true, anyNotValid);
    }
    return new MatchCheck(false, anyNotValid);
  }

  /** Deletes on-disk files for this store. Intended for test cleanup. */
  public void destruct() {
    try {
      Files.deleteIfExists(metaFile.toPath());
    } catch (IOException ioe) {
      LOG.warn("Failed to delete metadata file {}", metaFile, ioe);
    }
    try {
      Files.deleteIfExists(hdFile.toPath());
    } catch (IOException ioe) {
      LOG.warn("Failed to delete data file {}", hdFile, ioe);
    }
    try {
      Files.deleteIfExists(configFile.toPath());
    } catch (IOException ioe) {
      LOG.warn("Failed to delete config file {}", configFile, ioe);
    }
    try {
      Files.deleteIfExists(bloomFile.toPath());
    } catch (IOException ioe) {
      LOG.warn("Failed to delete bloom file {}", bloomFile, ioe);
    }
  }

  @Override
  public String toString() {
    return super.toString() + ":" + name;
  }

  /** Returns per-session (since process start) access statistics. */
  @Override
  public StoreAccessStats getSessionAccessStats() {
    /*
     * Returns counters for accesses during the current process session.
     * The session starts when the store is created and ends when it is closed.
     */
    return new StoreAccessStats() {

      @Override
      public long hits() {
        return hits.get() - initialHits;
      }

      @Override
      public long misses() {
        return misses.get() - initialMisses;
      }

      @Override
      public long falsePos() {
        return bloomFalsePos.get() - initialBloomFalsePos;
      }

      @Override
      public long writes() {
        return writes.get() - initialWrites;
      }
    };
  }

  /** Returns cumulative access statistics since the store was created. */
  @Override
  public StoreAccessStats getTotalAccessStats() {
    /* Returns cumulative counters persisted in the config file across restarts. */
    return new StoreAccessStats() {

      @Override
      public long hits() {
        return hits.get();
      }

      @Override
      public long misses() {
        return misses.get();
      }

      @Override
      public long falsePos() {
        return bloomFalsePos.get();
      }

      @Override
      public long writes() {
        return writes.get();
      }
    };
  }

  /** Testing only! Force all entries that say empty/unknown on the slot filter to empty/certain. */
  public void forceValidEmpty() {
    slotFilter.replaceAllEntries(0, SLOT_CHECKED);
  }

  /** Returns the underlying store (this instance). */
  @Override
  public FreenetStore<T> getUnderlyingStore() {
    return this;
  }

  /**
   * Only for testing (crude!) — waits for the cleaner to complete rebuild/resize. Uses default poll
   * delay/count tuned for unit tests.
   */
  void testingWaitForCleanerDone() throws InterruptedException {
    final int delay = 50;
    final int count = 100;
    boolean done = false;
    for (int i = 0; i < count; i++) {
      configLock.readLock().lock();
      try {
        done = (flags & FLAG_REBUILD_BLOOM) == 0;
      } finally {
        configLock.readLock().unlock();
      }
      if (done) {
        break;
      }
      Thread.sleep(delay);
    }
    if (!done) {
      throw new AssertionError();
    }
  }

  private boolean deleteCorruptedConfigAndMeta() {
    boolean deleted = false;
    try {
      deleted = Files.deleteIfExists(configFile.toPath());
    } catch (IOException ioe) {
      LOG.warn("Failed deleting config file after corruption: {}", configFile, ioe);
    }
    if (deleted) {
      File metaFileLocal = new File(baseDir, name + META_EXT);
      try {
        Files.deleteIfExists(metaFileLocal.toPath());
      } catch (IOException ioe) {
        LOG.warn("Failed deleting meta file after config corruption: {}", metaFileLocal, ioe);
      }
    }
    return deleted;
  }
}

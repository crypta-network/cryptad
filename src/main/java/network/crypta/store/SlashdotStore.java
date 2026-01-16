package network.crypta.store;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import network.crypta.keys.KeyVerifyException;
import network.crypta.node.stats.StoreAccessStats;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.ByteArrayWrapper;
import network.crypta.support.LRUMap;
import network.crypta.support.Ticker;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.TempBucketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A short‑term block cache with a strict LRU policy and a hard age limit.
 *
 * <p>This store keeps recently retrieved blocks for a limited time window (e.g., last tens of
 * minutes depending on configuration) and is typically used to reduce repeated network fetches. It
 * enforces both of the following constraints:
 *
 * <ul>
 *   <li>Strict LRU eviction when the maximum number of keys is exceeded.
 *   <li>Strict time‑based expiration: entries older than {@code maxLifetime} are removed.
 * </ul>
 *
 * <p>Block payloads are written into temporary buckets provided by {@link TempBucketFactory};
 * implementations commonly encrypt buckets at rest. The in‑memory index maps routing keys to disk
 * buckets and is synchronized for thread safety. Disk I/O is performed outside critical sections to
 * avoid holding locks during blocking operations.
 *
 * @param <T> block type stored in the cache; must implement {@link StorableBlock}
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public class SlashdotStore<T extends StorableBlock> implements FreenetStore<T> {
  private static final Logger LOG = LoggerFactory.getLogger(SlashdotStore.class);

  private static class DiskBlock {
    Bucket data;
    long lastAccessed;
  }

  private final TempBucketFactory bf;

  private long maxLifetime;

  private final long purgePeriod;

  // Purge scheduling: entries are purged on a periodic job and opportunistically on writes.
  // Drift of a few minutes is acceptable because maxLifetime is enforced on access and purge.

  private final Ticker ticker;

  private final LRUMap<ByteArrayWrapper, DiskBlock> blocksByRoutingKey;

  private final StoreCallback<T> callback;

  private int maxKeys;

  private long hits;
  private long misses;
  private long writes;

  private final int headerSize;
  private final int dataSize;
  private final int fullKeySize;

  /**
   * Creates a new time‑bounded LRU cache backed by temporary buckets.
   *
   * @param callback constructs blocks and provides fixed lengths for header/data/full key. The
   *     callback receives a reference to this store via {@link
   *     StoreCallback#setStore(FreenetStore)}.
   * @param maxKeys maximum number of cached entries (hard cap for the LRU index)
   * @param maxLifetime maximum age in milliseconds before an entry becomes eligible for eviction
   *     regardless of LRU position
   * @param purgePeriod interval in milliseconds between scheduled purge runs
   * @param ticker scheduler used for periodic purge tasks
   * @param tbf factory for on‑disk temporary buckets used to persist cached bytes
   */
  public SlashdotStore(
      StoreCallback<T> callback,
      int maxKeys,
      long maxLifetime,
      long purgePeriod,
      Ticker ticker,
      TempBucketFactory tbf) {
    this.callback = callback;
    this.blocksByRoutingKey = LRUMap.createSafeMap(ByteArrayWrapper.FAST_COMPARATOR);
    this.maxKeys = maxKeys;
    this.bf = tbf;
    this.ticker = ticker;
    this.maxLifetime = maxLifetime;
    this.purgePeriod = purgePeriod;
    callback.setStore(this);
    this.headerSize = callback.headerLength();
    this.dataSize = callback.dataLength();
    this.fullKeySize = callback.fullKeyLength();
    Runnable purgeOldData =
        new Runnable() {

          @Override
          public void run() {
            try {
              purgeOldData();
            } finally {
              SlashdotStore.this.ticker.queueTimedJob(this, SlashdotStore.this.purgePeriod);
            }
          }
        };
    ticker.queueTimedJob(purgeOldData, maxLifetime + purgePeriod);
  }

  /**
   * Fetches a cached block by routing key and reconstructs it via the callback.
   *
   * <p>If the entry exists and passes {@link StoreCallback#construct} verification, the method
   * returns the reconstructed block. Unless {@code dontPromote} is {@code true}, the entry is
   * promoted in the LRU. When not present or verification fails, the method returns {@code null}.
   *
   * @param routingKey key used to locate the entry in the LRU index
   * @param fullKey not used by this implementation; the persisted full key from disk is supplied to
   *     the callback
   * @param dontPromote when {@code true}, do not update LRU position on a hit
   * @param canReadClientCache forwarded to the callback during reconstruction
   * @param canReadSlashdotCache forwarded to the callback during reconstruction
   * @param ignoreOldBlocks accepted for interface compatibility; not used by this implementation
   * @param meta unused
   * @return the cached block or {@code null} if absent or invalid
   * @throws IOException on I/O errors while reading the bucket
   */
  @Override
  public T fetch(
      byte[] routingKey,
      byte[] fullKey,
      boolean dontPromote,
      boolean canReadClientCache,
      boolean canReadSlashdotCache,
      boolean ignoreOldBlocks,
      BlockMetadata meta)
      throws IOException {
    ByteArrayWrapper key = new ByteArrayWrapper(routingKey);
    DiskBlock block;
    long timeAccessed;
    synchronized (this) {
      block = blocksByRoutingKey.get(key);
      if (block == null) {
        misses++;
        return null;
      }
      timeAccessed = block.lastAccessed;
    }
    byte[] fk = new byte[fullKeySize];
    byte[] header = new byte[headerSize];
    byte[] data = new byte[dataSize];
    try (InputStream in = block.data.getInputStream();
        DataInputStream dis = new DataInputStream(in)) {
      dis.readFully(fk);
      dis.readFully(header);
      dis.readFully(data);
    }
    try {
      T ret =
          callback.construct(
              new StoreCallback.BlockPayload(data, header, routingKey, fk),
              new StoreCallback.ConstructOptions(canReadClientCache, canReadSlashdotCache, null),
              null);
      synchronized (this) {
        hits++;
        if (!dontPromote) {
          block.lastAccessed = System.currentTimeMillis();
          blocksByRoutingKey.push(key, block);
        }
      }
      if (LOG.isDebugEnabled())
        LOG.debug("Block was last accessed {}ms ago", (System.currentTimeMillis() - timeAccessed));
      return ret;
    } catch (KeyVerifyException _) {
      block.data.free();
      synchronized (this) {
        blocksByRoutingKey.removeKey(key);
        misses++;
      }
      return null;
    }
  }

  @Override
  public long getBloomFalsePositive() {
    // This cache uses no Bloom filter; indicate unsupported value.
    return -1;
  }

  /** Returns the configured maximum number of cached keys. */
  @Override
  public long getMaxKeys() {
    return maxKeys;
  }

  /** Returns the number of successful fetches since this store was created. */
  @Override
  public long hits() {
    return hits;
  }

  /** Returns the current number of entries held in the LRU index. */
  @Override
  public long keyCount() {
    return blocksByRoutingKey.size();
  }

  /** Returns the number of failed fetches since this store was created. */
  @Override
  public long misses() {
    return misses;
  }

  /**
   * Returns {@code true} if an entry for the routing key is currently in the index.
   *
   * <p>This is a fast in‑memory check; it does not validate the underlying bucket.
   */
  @Override
  public boolean probablyInStore(byte[] routingKey) {
    ByteArrayWrapper key = new ByteArrayWrapper(routingKey);
    return blocksByRoutingKey.containsKey(key);
  }

  /**
   * Inserts or updates a cached entry for the block's routing key.
   *
   * <p>The method persists {@code fullKey + header + data} into a temporary bucket and inserts the
   * new {@code DiskBlock} at the head of the LRU. If an entry already exists, the previous bucket
   * is released during the later purge step.
   *
   * @param block block providing routing and full keys for indexing
   * @param data payload bytes (length must match {@link StoreCallback#dataLength()})
   * @param header header bytes (length must match {@link StoreCallback#headerLength()})
   * @param overwrite accepted for interface compatibility; not used by this implementation
   * @param isOldBlock accepted for interface compatibility; admission does not differ by age
   * @throws IOException if writing to the bucket fails
   * @throws KeyCollisionException if the store detects an unrecoverable key collision
   */
  @Override
  public void put(T block, byte[] data, byte[] header, boolean overwrite, boolean isOldBlock)
      throws IOException, KeyCollisionException {
    byte[] routingkey = block.getRoutingKey();
    byte[] fullKey = block.getFullKey();

    Bucket bucket = bf.makeBucket((long) fullKeySize + dataSize + headerSize);
    try (OutputStream os = bucket.getOutputStream()) {
      os.write(fullKey);
      os.write(header);
      os.write(data);
    }

    DiskBlock stored = new DiskBlock();
    stored.data = bucket;
    purgeOldData(new ByteArrayWrapper(routingkey), stored);
  }

  /**
   * Sets the maximum number of cached keys and optionally triggers immediate compaction.
   *
   * @param maxStoreKeys new hard cap; must be representable as a 32‑bit integer
   * @param shrinkNow when {@code true}, evicts excess/expired entries synchronously; otherwise, a
   *     purge job is queued immediately
   * @throws IOException not thrown by this implementation; declared for interface compatibility
   * @throws IllegalArgumentException if {@code maxStoreKeys} exceeds {@link Integer#MAX_VALUE}
   */
  @Override
  public void setMaxKeys(long maxStoreKeys, boolean shrinkNow) throws IOException {
    if (maxStoreKeys > Integer.MAX_VALUE) throw new IllegalArgumentException();
    this.maxKeys = (int) maxStoreKeys;
    if (shrinkNow) {
      purgeOldData();
    } else {
      ticker.queueTimedJob(this::purgeOldData, 0);
    }
  }

  /** Returns the number of successful insertions since this store was created. */
  @Override
  public long writes() {
    return writes;
  }

  /**
   * Purges expired entries and trims the LRU to {@code maxKeys}.
   *
   * <p>This method may free buckets; I/O occurs outside the synchronized block.
   */
  protected void purgeOldData() {
    purgeOldData(null, null);
  }

  private void purgeOldData(ByteArrayWrapper key, DiskBlock addFirst) {
    List<DiskBlock> blocks = null;
    DiskBlock oldBlock;
    synchronized (this) {
      long now = System.currentTimeMillis();
      if (addFirst != null) {
        addFirst.lastAccessed = now;
        oldBlock = blocksByRoutingKey.push(key, addFirst);
        if (oldBlock != null) {
          blocks = new ArrayList<>();
          blocks.add(oldBlock);
        }
        writes++;
      }
      while (!blocksByRoutingKey.isEmpty()) {
        DiskBlock block = blocksByRoutingKey.peekValue();
        boolean shouldStop;
        if (block == null) {
          shouldStop = true; // Defensive: no candidate to evict or promote
        } else {
          boolean withinLifetime = (now - block.lastAccessed) < maxLifetime;
          boolean underKeyLimit = blocksByRoutingKey.size() < maxKeys;
          shouldStop = withinLifetime && underKeyLimit;
        }
        if (shouldStop) break;
        if (blocks == null) blocks = new ArrayList<>();
        blocks.add(block);
        blocksByRoutingKey.popValue();
      }
    }
    if (blocks == null) return;
    for (DiskBlock block : blocks) {
      block.data.free();
    }
  }

  /** Returns the configured maximum lifetime in milliseconds. */
  public synchronized Long getLifetime() {
    return maxLifetime;
  }

  /** Sets the maximum lifetime in milliseconds applied to future evictions. */
  public synchronized void setLifetime(Long val) {
    maxLifetime = val;
  }

  /**
   * Returns a view of the current session counters.
   *
   * <p>The returned object reads the live counters when its methods are called; it is not a
   * point‑in‑time snapshot.
   */
  @Override
  public StoreAccessStats getSessionAccessStats() {
    return new StoreAccessStats() {

      @Override
      public long hits() {
        return hits;
      }

      @Override
      public long misses() {
        return misses;
      }

      @Override
      public long falsePos() {
        return 0;
      }

      @Override
      public long writes() {
        return writes;
      }
    };
  }

  /** Returns {@code null}; this store does not aggregate total access statistics. */
  @Override
  public StoreAccessStats getTotalAccessStats() {
    return null;
  }

  /**
   * Starts the store if necessary.
   *
   * <p>This implementation has no on‑disk structures to initialize and returns {@code false}.
   *
   * @return {@code false}; nothing to start
   * @throws IOException never thrown by this implementation
   */
  @Override
  public boolean start(Ticker ticker, boolean longStart) throws IOException {
    return false;
  }

  /** No‑op: this store does not surface user alerts. */
  @Override
  public void setUserAlertManager(UserAlertManager userAlertManager) {
    // Intentionally no operation
  }

  /** Returns {@code this}; there is no additional underlying store layer. */
  @Override
  public FreenetStore<T> getUnderlyingStore() {
    return this;
  }

  /** No‑op close; buckets are freed on eviction and process exit. */
  @Override
  public void close() {
    // Intentionally no operation
  }
}

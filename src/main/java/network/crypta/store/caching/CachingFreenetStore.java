package network.crypta.store.caching;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import network.crypta.keys.KeyVerifyException;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.store.BlockMetadata;
import network.crypta.store.FetchOptions;
import network.crypta.store.FreenetStore;
import network.crypta.store.KeyCollisionException;
import network.crypta.store.ProxyFreenetStore;
import network.crypta.store.StorableBlock;
import network.crypta.store.StoreCallback;
import network.crypta.support.ByteArrayWrapper;
import network.crypta.support.LRUMap;
import network.crypta.support.Ticker;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An in-memory, LRU-backed write-through cache in front of a {@link FreenetStore}.
 *
 * <p>This store keeps recently written blocks in a memory cache keyed by routing key and
 * opportunistically serves reads from that cache. Depending on collision settings and the {@code
 * overwrite} flag, it may defer writing through to the underlying store until the cached entry is
 * evicted (via {@link #pushLeastRecentlyBlock()}) or write through immediately. The cache uses a
 * {@link LRUMap} and a {@link ReadWriteLock} to allow concurrent reads while serializing mutations.
 *
 * <p>Thread-safety: all access to the internal map is guarded by {@link #configLock}. Public
 * methods are safe for concurrent use. Shutdown sets a guard flag so new puts are rejected while
 * allowing the underlying store to close cleanly.
 *
 * @param <T> concrete {@link StorableBlock} type handled by the store
 * @author Simon Vocella <voxsim@gmail.com>
 */
public class CachingFreenetStore<T extends StorableBlock> extends ProxyFreenetStore<T> {
  private static final Logger LOG = LoggerFactory.getLogger(CachingFreenetStore.class);

  // When true, reject new puts; set during shutdown.
  private boolean shuttingDown;

  /* True once {@link #close()} has been invoked to ensure idempotent shutdown. */
  private final AtomicBoolean closeCalled = new AtomicBoolean(false);

  private final LRUMap<ByteArrayWrapper, Block<T>> blocksByRoutingKey;
  private final StoreCallback<T> callback;
  private final boolean collisionPossible;
  private final ReadWriteLock configLock = new ReentrantReadWriteLock();
  private final CachingFreenetStoreTracker tracker;
  private final int sizeBlock;

  // Logging relies on SLF4J; guard debug work with LOG.isDebugEnabled().

  private static final class Block<T> {
    T storable;
    byte[] data;
    byte[] header;
    boolean overwrite;
    boolean isOldBlock;
  }

  /**
   * Creates a caching wrapper around an existing store.
   *
   * <p>Side effects: registers a high-priority shutdown job and calls {@link
   * StoreCallback#setStore(FreenetStore)} on the provided callback.
   *
   * @param callback callback used to construct blocks and query behavior flags
   * @param backDatastore underlying persistent store to delegate reads/writes to
   * @param tracker tracker that accounts for approximate memory usage of cached entries
   */
  public CachingFreenetStore(
      StoreCallback<T> callback,
      FreenetStore<T> backDatastore,
      CachingFreenetStoreTracker tracker) {
    super(backDatastore);
    this.callback = callback;
    SemiOrderedShutdownHook shutdownHook = SemiOrderedShutdownHook.get();
    this.blocksByRoutingKey = LRUMap.createSafeMap(ByteArrayWrapper.FAST_COMPARATOR);
    this.collisionPossible = callback.collisionPossible();
    this.shuttingDown = false;
    this.tracker = tracker;
    this.sizeBlock = callback.getTotalBlockSize();

    callback.setStore(this);
    shutdownHook.addEarlyJob(
        new NativeThread(
            "Close CachingFreenetStore", NativeThread.PriorityLevel.HIGH_PRIORITY.value, true) {
          @Override
          public void realRun() {
            innerClose(); // SaltedHashFS has its own shutdown job.
          }
        });
  }

  /**
   * Fetches a block by routing key, consulting the in-memory cache first.
   *
   * <p>If a cached entry exists, the block is reconstructed using the injected {@link
   * StoreCallback}. If verification fails, the error is logged and the call falls back to the
   * underlying store. When the cache misses, the request is delegated directly to {@code
   * backDatastore}.
   *
   * @param routingKey the routing key to lookup (must not be {@code null})
   * @param fullKey the full key used by the underlying store; passed through on fallback
   * @param dontPromote whether the underlying store should avoid promotion on read
   * @param canReadClientCache whether the client cache may be consulted during read
   * @param canReadSlashdotCache whether the slashdot cache may be consulted during read
   * @param ignoreOldBlocks whether to ignore blocks marked as old
   * @param meta holder for metadata populated during read (optional)
   * @return the reconstructed block, or the result from the underlying store; may be {@code null}
   *     if no block is present
   * @throws IOException if the underlying store throws while reading
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
    ByteArrayWrapper key = new ByteArrayWrapper(routingKey);

    Block<T> block;

    configLock.readLock().lock();
    try {
      block = blocksByRoutingKey.get(key);
    } finally {
      configLock.readLock().unlock();
    }

    if (block != null) {
      try {
        return this.callback.construct(
            new StoreCallback.BlockPayload(
                block.data, block.header, routingKey, block.storable.getFullKey()),
            new StoreCallback.ConstructOptions(
                options.canReadClientCache(), options.canReadSlashdotCache(), options.meta()),
            null);
      } catch (KeyVerifyException e) {
        LOG.error("Error in fetching for CachingFreenetStore: {}", e, e);
      }
    }

    return backDatastore.fetch(routingKey, fullKey, options);
  }

  /**
   * Returns a fast, approximate membership result.
   *
   * <p>Checks the local cache first, then delegates to the underlying store. This call may return
   * {@code true} for keys that are not ultimately readable, but should avoid false negatives for
   * entries currently resident in the cache.
   *
   * @param routingKey the routing key to test
   * @return {@code true} if the key is likely present in either cache or backing store
   */
  @Override
  public boolean probablyInStore(byte[] routingKey) {
    ByteArrayWrapper key = new ByteArrayWrapper(routingKey);
    Block<T> block;

    configLock.readLock().lock();
    try {
      block = blocksByRoutingKey.get(key);
    } finally {
      configLock.readLock().unlock();
    }

    return block != null || backDatastore.probablyInStore(routingKey);
  }

  /**
   * Puts a block into the cache and possibly the underlying store.
   *
   * <p>Behavior depends on collision policy and {@code overwrite}:
   *
   * <ul>
   *   <li>If collisions are possible and {@code overwrite == false}, an existing different block
   *       with the same routing key causes a {@link KeyCollisionException}. If the same block is
   *       already cached, the write-through is skipped.
   *   <li>Otherwise, the block is added/updated in the LRU cache and may be written through
   *       immediately. When deferred, eviction will push it via {@link #pushLeastRecentlyBlock()}.
   * </ul>
   *
   * <p>When shutdown is in progress, new puts are rejected for caching and delegated directly to
   * the backing store when applicable.
   *
   * @param block the block descriptor
   * @param data the block payload bytes
   * @param header optional header bytes associated with the block
   * @param overwrite whether an existing entry with the same routing key may be overwritten
   * @param isOldBlock whether the block is marked as old in metadata
   * @throws IOException if the underlying store throws while writing through
   * @throws KeyCollisionException if a different block already exists and overwriting is disabled
   */
  @Override
  public void put(T block, byte[] data, byte[] header, boolean overwrite, boolean isOldBlock)
      throws IOException, KeyCollisionException {
    byte[] routingKey = block.getRoutingKey();
    final ByteArrayWrapper key = new ByteArrayWrapper(routingKey);

    Block<T> storeBlock = new Block<>();
    storeBlock.storable = block;
    storeBlock.data = data;
    storeBlock.header = header;
    storeBlock.overwrite = overwrite;
    storeBlock.isOldBlock = isOldBlock;

    CacheDecision decision;
    configLock.writeLock().lock();
    try {
      decision = decideCache(block, key, storeBlock, routingKey, overwrite);
    } finally {
      configLock.writeLock().unlock();
    }

    if (decision == CacheDecision.SKIP_BACKSTORE_PUT) return;
    if (decision == CacheDecision.DONT_CACHE)
      backDatastore.put(block, data, header, overwrite, isOldBlock);
  }

  // Attempts to cache the block, pushing it on the LRU. Returns whether it was cached.
  private boolean maybeCacheAndPush(
      ByteArrayWrapper key, Block<T> previousBlock, Block<T> storeBlock) {
    boolean cacheIt = true;
    if (previousBlock == null) cacheIt = tracker.add(sizeBlock);
    if (cacheIt) blocksByRoutingKey.push(key, storeBlock);
    return cacheIt;
  }

  private enum CacheDecision {
    CACHE,
    DONT_CACHE,
    SKIP_BACKSTORE_PUT
  }

  /*
   * Decide whether to cache, write through, or skip the backing-store writing. The result depends on
   * whether we are shutting down, whether collisions are possible, current LRU state, and the
   * overwrite flag.
   */
  private CacheDecision decideCache(
      T block, ByteArrayWrapper key, Block<T> storeBlock, byte[] routingKey, boolean overwrite)
      throws KeyCollisionException {
    if (shuttingDown) return CacheDecision.DONT_CACHE;

    Block<T> previousBlock = blocksByRoutingKey.get(key);

    if (collisionPossible && !overwrite) {
      if (previousBlock != null) {
        if (block.equals(previousBlock.storable)) return CacheDecision.SKIP_BACKSTORE_PUT;
        throw new KeyCollisionException();
      }
      if (backDatastore.probablyInStore(routingKey)) return CacheDecision.DONT_CACHE;
      return maybeCacheAndPush(key, null, storeBlock)
          ? CacheDecision.CACHE
          : CacheDecision.DONT_CACHE;
    }

    return maybeCacheAndPush(key, previousBlock, storeBlock)
        ? CacheDecision.CACHE
        : CacheDecision.DONT_CACHE;
  }

  /**
   * Flushes the least-recently used cached entry to the backing store.
   *
   * <p>This method peeks the LRU entry, writes it to {@code backDatastore}, and then attempts to
   * remove the exact same version from the cache. If the entry changed concurrently (e.g., an
   * overwriting occurred while writing), the removal is skipped to avoid dropping updated data.
   *
   * @return {@code sizeBlock} (bytes) when a block is written and removed; {@code 0} when a block
   *     was written but not removed due to a concurrent change; {@code -1} when the cache is empty
   */
  long pushLeastRecentlyBlock() {
    Block<T> block;
    ByteArrayWrapper key;

    configLock.writeLock().lock();
    try {
      block = blocksByRoutingKey.peekValue();
      if (block == null) return -1;
      key = blocksByRoutingKey.peekKey();
    } finally {
      configLock.writeLock().unlock();
    }

    try {
      backDatastore.put(
          block.storable, block.data, block.header, block.overwrite, block.isOldBlock);
    } catch (IOException e) {
      LOG.error("Error in pushAll for CachingFreenetStore: {}", e, e);
    } catch (KeyCollisionException e) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("KeyCollisionException in pushAll for CachingFreenetStore", e);
      }
    }

    configLock.writeLock().lock();
    try {
      Block<T> currentVersionOfBlock = blocksByRoutingKey.get(key);

      // The entry may have been updated by a concurrent put(overwrite=true); do not remove if so.
      if (currentVersionOfBlock != null
          && currentVersionOfBlock.storable.equals(block.storable)
          && blocksByRoutingKey.removeKey(key)) return sizeBlock;
    } finally {
      configLock.writeLock().unlock();
    }
    return 0;
  }

  /**
   * Starts this store and the underlying store.
   *
   * <p>Registers this instance with the {@link CachingFreenetStoreTracker} and delegates startup to
   * the backing store.
   *
   * @param ticker a ticker for start-up progress reporting
   * @param longStart whether a long/expensive start-up path should be used
   * @return {@code true} if the backing store starts successfully
   * @throws IOException if the underlying store fails to start
   */
  @Override
  public boolean start(Ticker ticker, boolean longStart) throws IOException {
    tracker.registerCachingFS(this);
    return this.backDatastore.start(ticker, longStart);
  }

  /**
   * Closes this store and then the underlying store.
   *
   * <p>Idempotent: only the first invocation performs work. Sets the shutdown guard so later puts
   * are rejected for caching.
   */
  @Override
  public void close() {
    if (closeCalled.compareAndSet(false, true)) {
      innerClose();
      backDatastore.close();
    }
  }

  /** Closes only this layer; does not close the underlying store. */
  private void innerClose() {
    configLock.writeLock().lock();
    try {
      shuttingDown = true;
      tracker.unregisterCachingFS(this);
    } finally {
      configLock.writeLock().unlock();
    }
  }

  /**
   * Visible for testing: returns whether the cache currently holds no entries.
   *
   * @return {@code true} if the internal LRU map is empty
   */
  boolean isEmpty() {
    boolean isEmpty;
    configLock.readLock().lock();
    try {
      isEmpty = this.blocksByRoutingKey.isEmpty();
    } finally {
      configLock.readLock().unlock();
    }
    return isEmpty;
  }
}

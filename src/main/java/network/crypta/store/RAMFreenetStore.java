package network.crypta.store;

import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;
import network.crypta.keys.KeyVerifyException;
import network.crypta.node.stats.StoreAccessStats;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.ByteArrayWrapper;
import network.crypta.support.LRUMap;
import network.crypta.support.Ticker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * In-memory LRU store for {@link StorableBlock} instances keyed by routing key.
 *
 * <p>This implementation is intended for debugging or simulation scenarios where a full persistent
 * store is unnecessary. Entries are kept in an {@link LRUMap} capped by {@code maxKeys}; the store
 * evicts least-recently used entries on insertion and tracks hits, misses, and writes for
 * lightweight reporting. Retrieval delegates block construction to the configured {@link
 * StoreCallback}, which also decides whether full keys are stored.
 *
 * <p>Most accessors and mutating operations are synchronized on the store instance. Operations that
 * bypass synchronization, such as {@link #clear()} and {@link #migrateTo(StoreCallback, boolean)},
 * should not be interleaved with concurrent reads or writes without external coordination.
 *
 * <ul>
 *   <li>Provides an LRU-backed, in-memory key/value store.
 *   <li>Records basic access statistics for the current session.
 *   <li>Supports optional migration into another {@link StoreCallback}.
 * </ul>
 *
 * @param <T> concrete {@link StorableBlock} type constructed by the callback
 */
public class RAMFreenetStore<T extends StorableBlock> implements FreenetStore<T> {
  private static final Logger LOG = LoggerFactory.getLogger(RAMFreenetStore.class);

  private static final class Block {
    byte[] header;
    byte[] data;
    byte[] fullKey;
    boolean oldBlock;
  }

  private final LRUMap<ByteArrayWrapper, Block> blocksByRoutingKey;

  private final StoreCallback<T> callback;

  private int maxKeys;

  private long hits;
  private long misses;
  private long writes;

  /**
   * Create an in-memory store with a fixed maximum number of keys.
   *
   * <p>The store registers itself with the supplied {@link StoreCallback} and uses the callback for
   * block construction, collision handling, and optional full-key retention. The maximum size is
   * enforced by evicting least-recently used entries as new blocks are inserted.
   *
   * <p>This constructor does not allocate storage beyond the internal map; entries are only created
   * when {@link #put(StorableBlock, byte[], byte[], boolean, boolean)} is called.
   *
   * @param callback callback that constructs blocks and receives the store reference; must not be
   *     {@code null}
   * @param maxKeys maximum number of routing keys to retain before evicting; values are treated as
   *     a simple count and should be positive
   */
  public RAMFreenetStore(StoreCallback<T> callback, int maxKeys) {
    this.callback = callback;
    this.blocksByRoutingKey = LRUMap.createSafeMap(ByteArrayWrapper.FAST_COMPARATOR);
    this.maxKeys = maxKeys;
    callback.setStore(this);
  }

  @Override
  @SuppressWarnings("java:S107") // delegator to FetchOptions overload
  public synchronized T fetch(
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
  public synchronized T fetch(byte[] routingKey, byte[] fullKey, FetchOptions options)
      throws IOException {
    ByteArrayWrapper key = new ByteArrayWrapper(routingKey);
    Block block = blocksByRoutingKey.get(key);
    if (block == null) {
      misses++;
      return null;
    }
    if (options.ignoreOldBlocks() && block.oldBlock) {
      LOG.info("Ignoring old block");
      return null;
    }
    try {
      T ret =
          callback.construct(
              new StoreCallback.BlockPayload(block.data, block.header, routingKey, block.fullKey),
              new StoreCallback.ConstructOptions(
                  options.canReadClientCache(), options.canReadSlashdotCache(), options.meta()),
              null);
      hits++;
      if (!options.dontPromote()) blocksByRoutingKey.push(key, block);
      if (options.meta() != null && block.oldBlock) options.meta().setOldBlock();
      return ret;
    } catch (KeyVerifyException _) {
      blocksByRoutingKey.removeKey(key);
      misses++;
      return null;
    }
  }

  @Override
  public synchronized long getMaxKeys() {
    return maxKeys;
  }

  @Override
  public synchronized long hits() {
    return hits;
  }

  @Override
  public synchronized long keyCount() {
    return blocksByRoutingKey.size();
  }

  @Override
  public synchronized long misses() {
    return misses;
  }

  @Override
  public synchronized void put(
      T block, byte[] data, byte[] header, boolean overwrite, boolean isOldBlock)
      throws KeyCollisionException {
    byte[] routingKey = block.getRoutingKey();
    byte[] fullKey = block.getFullKey();

    writes++;
    ByteArrayWrapper key = new ByteArrayWrapper(routingKey);
    Block existing = blocksByRoutingKey.get(key);
    boolean storeFullKeys = callback.storeFullKeys();

    if (existing != null) {
      handleExistingBlock(existing, data, header, overwrite, isOldBlock, storeFullKeys, fullKey);
      return;
    }

    addNewBlock(key, data, header, isOldBlock, storeFullKeys, fullKey);
    evictIfNecessary();
  }

  private boolean isSameContent(
      Block oldBlock, byte[] data, byte[] header, boolean storeFullKeys, byte[] fullKey) {
    return Arrays.equals(oldBlock.data, data)
        && Arrays.equals(oldBlock.header, header)
        && (!storeFullKeys || Arrays.equals(oldBlock.fullKey, fullKey));
  }

  private void overwriteExistingBlock(
      Block oldBlock,
      byte[] data,
      byte[] header,
      boolean storeFullKeys,
      byte[] fullKey,
      boolean isOldBlock) {
    oldBlock.data = data;
    oldBlock.header = header;
    if (storeFullKeys) oldBlock.fullKey = fullKey;
    oldBlock.oldBlock = isOldBlock;
  }

  private void handleExistingBlock(
      Block oldBlock,
      byte[] data,
      byte[] header,
      boolean overwrite,
      boolean isOldBlock,
      boolean storeFullKeys,
      byte[] fullKey)
      throws KeyCollisionException {
    if (callback.collisionPossible()) {
      if (isSameContent(oldBlock, data, header, storeFullKeys, fullKey)) {
        if (!isOldBlock) oldBlock.oldBlock = false;
        return;
      }
      if (overwrite) {
        overwriteExistingBlock(oldBlock, data, header, storeFullKeys, fullKey, isOldBlock);
      } else {
        throw new KeyCollisionException();
      }
      return;
    }
    if (!isOldBlock) oldBlock.oldBlock = false;
  }

  private void addNewBlock(
      ByteArrayWrapper key,
      byte[] data,
      byte[] header,
      boolean isOldBlock,
      boolean storeFullKeys,
      byte[] fullKey) {
    Block storeBlock = new Block();
    storeBlock.data = data;
    storeBlock.header = header;
    if (storeFullKeys) storeBlock.fullKey = fullKey;
    storeBlock.oldBlock = isOldBlock;
    blocksByRoutingKey.push(key, storeBlock);
  }

  private void evictIfNecessary() {
    while (blocksByRoutingKey.size() > maxKeys) {
      blocksByRoutingKey.popKey();
    }
  }

  @Override
  public synchronized void setMaxKeys(long maxStoreKeys, boolean shrinkNow) throws IOException {
    this.maxKeys = (int) Math.min(Integer.MAX_VALUE, maxStoreKeys);
    // Always shrink now regardless of parameter as we will shrink on the next put() anyway.
    while (blocksByRoutingKey.size() > maxKeys) {
      blocksByRoutingKey.popKey();
    }
  }

  @Override
  public long writes() {
    return writes;
  }

  @Override
  public long getBloomFalsePositive() {
    return -1;
  }

  @Override
  public boolean probablyInStore(byte[] routingKey) {
    ByteArrayWrapper key = new ByteArrayWrapper(routingKey);
    return blocksByRoutingKey.get(key) != null;
  }

  /**
   * Remove all entries from the in-memory map immediately.
   *
   * <p>This clears routing-key mappings without adjusting hit/miss counters. Callers should ensure
   * no concurrent readers or writers are active, because this method is not synchronized and does
   * not coordinate with ongoing {@link #fetch(byte[], byte[], boolean, boolean, boolean, boolean,
   * BlockMetadata)} or {@link #put(StorableBlock, byte[], byte[], boolean, boolean)} operations.
   */
  public void clear() {
    blocksByRoutingKey.clear();
  }

  /**
   * Copy every stored block into another store callback.
   *
   * <p>Each entry is reconstructed using the current callback and then written into the target
   * store. Collisions in the target store are ignored, and any block that fails verification is
   * skipped. The operation iterates over the current key enumeration and does not update this
   * store's counters or ordering.
   *
   * <p>Callers should treat this as a snapshot-like transfer: changes to this store during the
   * migration can lead to missed or duplicated entries, so coordinate externally if consistency
   * matters.
   *
   * @param target destination callback whose underlying store receives the reconstructed blocks
   * @param canReadClientCache whether reconstructed blocks may read from the client cache during
   *     construction
   * @throws IOException if the target store rejects the writing with an I/O failure
   */
  public void migrateTo(StoreCallback<T> target, boolean canReadClientCache) throws IOException {
    Enumeration<ByteArrayWrapper> keys = blocksByRoutingKey.keys();
    while (keys.hasMoreElements()) {
      ByteArrayWrapper routingKeyWrapped = keys.nextElement();
      byte[] routingKey = routingKeyWrapped.get();
      Block block = blocksByRoutingKey.get(routingKeyWrapped);

      boolean skip = (block == null);
      T ret = null;
      if (!skip) {
        try {
          ret =
              callback.construct(
                  new StoreCallback.BlockPayload(
                      block.data, block.header, routingKey, block.fullKey),
                  new StoreCallback.ConstructOptions(canReadClientCache, false, null),
                  null);
        } catch (KeyVerifyException e) {
          LOG.error("Caught while migrating: {}", e, e);
          skip = true;
        }
      }
      if (!skip) {
        try {
          target.getStore().put(ret, block.data, block.header, false, block.oldBlock);
        } catch (KeyCollisionException _) {
          // Ignore
        }
      }
    }
  }

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

  @Override
  public StoreAccessStats getTotalAccessStats() {
    return null;
  }

  @Override
  public boolean start(Ticker ticker, boolean longStart) throws IOException {
    return false;
  }

  @Override
  public void setUserAlertManager(UserAlertManager userAlertManager) {
    // Do nothing
  }

  @Override
  public FreenetStore<T> getUnderlyingStore() {
    return this;
  }

  @Override
  public void close() {
    // Do nothing
  }
}

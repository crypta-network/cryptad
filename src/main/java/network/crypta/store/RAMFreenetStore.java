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
 * LRU in memory store.
 *
 * <p>For debugging / simulation only
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

  public RAMFreenetStore(StoreCallback<T> callback, int maxKeys) {
    this.callback = callback;
    this.blocksByRoutingKey = LRUMap.createSafeMap(ByteArrayWrapper.FAST_COMPARATOR);
    this.maxKeys = maxKeys;
    callback.setStore(this);
  }

  @Override
  public synchronized T fetch(
      byte[] routingKey,
      byte[] fullKey,
      boolean dontPromote,
      boolean canReadClientCache,
      boolean canReadSlashdotCache,
      boolean ignoreOldBlocks,
      BlockMetadata meta)
      throws IOException {
    ByteArrayWrapper key = new ByteArrayWrapper(routingKey);
    Block block = blocksByRoutingKey.get(key);
    if (block == null) {
      misses++;
      return null;
    }
    if (ignoreOldBlocks && block.oldBlock) {
      LOG.info("Ignoring old block");
      return null;
    }
    try {
      T ret =
          callback.construct(
              block.data,
              block.header,
              routingKey,
              block.fullKey,
              canReadClientCache,
              canReadSlashdotCache,
              meta,
              null);
      hits++;
      if (!dontPromote) blocksByRoutingKey.push(key, block);
      if (meta != null && block.oldBlock) meta.setOldBlock();
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

  public void clear() {
    blocksByRoutingKey.clear();
  }

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
                  block.data,
                  block.header,
                  routingKey,
                  block.fullKey,
                  canReadClientCache,
                  false,
                  null,
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

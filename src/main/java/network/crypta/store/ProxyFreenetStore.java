package network.crypta.store;

import java.io.IOException;
import network.crypta.node.stats.StoreAccessStats;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.Ticker;

/**
 * Delegating base implementation of {@link FreenetStore}.
 *
 * <p>This proxy forwards all operations to a supplied underlying store. Subclasses can override
 * specific methods to add behavior such as caching, rate limiting, logging, or metrics while
 * relying on the delegate for the default implementation. By itself this class does not change the
 * concurrency or persistence semantics of the underlying store.
 *
 * @param <T> concrete {@link StorableBlock} type handled by this store
 */
public abstract class ProxyFreenetStore<T extends StorableBlock> implements FreenetStore<T> {

  /** Store that receives all delegated operations. Assigned at construction and never changed. */
  protected final FreenetStore<T> backDatastore;

  /**
   * Construct a proxy that delegates to {@code backDatastore}.
   *
   * @param backDatastore underlying store that performs the actual work; must not be {@code null}.
   */
  protected ProxyFreenetStore(FreenetStore<T> backDatastore) {
    this.backDatastore = backDatastore;
  }

  /** {@inheritDoc} Delegates to the underlying store. */
  @Override
  public long getBloomFalsePositive() {
    return backDatastore.getBloomFalsePositive();
  }

  /** {@inheritDoc} Delegates to the underlying store. */
  @Override
  public long getMaxKeys() {
    return backDatastore.getMaxKeys();
  }

  /** {@inheritDoc} Delegates to the underlying store. */
  @Override
  public long hits() {
    return backDatastore.hits();
  }

  /** {@inheritDoc} Delegates to the underlying store. */
  @Override
  public long keyCount() {
    return backDatastore.keyCount();
  }

  /** {@inheritDoc} Delegates to the underlying store. */
  @Override
  public long misses() {
    return backDatastore.misses();
  }

  /** {@inheritDoc} Delegates to the underlying store. */
  @Override
  public void setMaxKeys(long maxStoreKeys, boolean shrinkNow) throws IOException {
    backDatastore.setMaxKeys(maxStoreKeys, shrinkNow);
  }

  /** {@inheritDoc} Delegates to the underlying store. */
  @Override
  public long writes() {
    return backDatastore.writes();
  }

  /** {@inheritDoc} Delegates to the underlying store. */
  @Override
  public StoreAccessStats getSessionAccessStats() {
    return backDatastore.getSessionAccessStats();
  }

  /** {@inheritDoc} Delegates to the underlying store. */
  @Override
  public StoreAccessStats getTotalAccessStats() {
    return backDatastore.getTotalAccessStats();
  }

  /** {@inheritDoc} Forwards the manager to the underlying store. */
  @Override
  public void setUserAlertManager(UserAlertManager userAlertManager) {
    this.backDatastore.setUserAlertManager(userAlertManager);
  }

  /** {@inheritDoc} Returns the delegate for this proxy. */
  @Override
  public FreenetStore<T> getUnderlyingStore() {
    return this.backDatastore;
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation performs no additional logic and simply delegates to the underlying
   * store.
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
    return backDatastore.fetch(
        routingKey,
        fullKey,
        dontPromote,
        canReadClientCache,
        canReadSlashdotCache,
        ignoreOldBlocks,
        meta);
  }

  @Override
  public T fetch(byte[] routingKey, byte[] fullKey, FetchOptions options) throws IOException {
    return backDatastore.fetch(routingKey, fullKey, options);
  }

  /** {@inheritDoc} Delegates to the underlying store. */
  @Override
  public void put(T block, byte[] data, byte[] header, boolean overwrite, boolean oldBlock)
      throws IOException, KeyCollisionException {
    backDatastore.put(block, data, header, overwrite, oldBlock);
  }

  /** {@inheritDoc} Delegates to the underlying store. */
  @Override
  public boolean probablyInStore(byte[] routingKey) {
    return backDatastore.probablyInStore(routingKey);
  }

  /** {@inheritDoc} Delegates to the underlying store. */
  @Override
  public boolean start(Ticker ticker, boolean longStart) throws IOException {
    return backDatastore.start(ticker, longStart);
  }

  /** {@inheritDoc} Delegates to the underlying store. */
  @Override
  public void close() {
    backDatastore.close();
  }
}

package network.crypta.store;

import java.io.IOException;
import network.crypta.node.stats.StoreAccessStats;
import network.crypta.store.alerts.StoreAlertSink;
import network.crypta.support.Ticker;

/**
 * A no-op {@link FreenetStore} implementation.
 *
 * <p>This store accepts all operations but does not persist or retrieve any data. Reads always
 * return {@code null} or {@code false}, counters report {@code 0}, and mutating operations are
 * effective no-ops. This is useful in configurations where a store is required by the surrounding
 * API, but storage must be disabled, such as tests, dry runs, or memory-constrained environments.
 *
 * <p>Threading: this class keeps no internal state and performs no I/O; calls may be made from any
 * thread without additional synchronization.
 *
 * @param <T> the block type stored by the implementation, constrained to {@link StorableBlock}
 */
public class NullFreenetStore<T extends StorableBlock> implements FreenetStore<T> {

  /**
   * Constructs a null store and registers it with the provided callback.
   *
   * <p>The callback is informed about this store via {@code callback.setStore(this)} so callers can
   * get a reference to the effective store instance.
   *
   * @param callback initialization callback that receives the store reference; must not be null
   */
  public NullFreenetStore(StoreCallback<T> callback) {
    callback.setStore(this);
  }

  /**
   * Attempts to fetch a block, always returning {@code null}.
   *
   * <p>No metadata is populated because nothing is read. All parameters are accepted to satisfy the
   * {@link FreenetStore} contract but are ignored.
   *
   * @param routingKey the routing key; ignored
   * @param fullKey the full key; ignored
   * @param dontPromote if true, the store should not promote on read; ignored
   * @param canReadClientCache whether client cache reads are allowed; ignored
   * @param canReadSlashdotCache whether slashdot cache reads are allowed; ignored
   * @param ignoreOldBlocks whether obsolete blocks should be ignored; ignored
   * @param meta optional metadata holder; not modified
   * @return always {@code null}
   * @throws IOException never thrown by this implementation
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
    // No block is available; leave {@code meta} unchanged.
    return null;
  }

  /** Returns the current Bloom filter false positive count, always {@code 0}. */
  @Override
  public long getBloomFalsePositive() {
    return 0;
  }

  /** Returns the configured key capacity, always {@code 0} for a disabled store. */
  @Override
  public long getMaxKeys() {
    return 0;
  }

  /** Returns the number of successful reads, always {@code 0}. */
  @Override
  public long hits() {
    return 0;
  }

  /** Returns the number of stored keys, always {@code 0}. */
  @Override
  public long keyCount() {
    return 0;
  }

  /** Returns the number of failed reads, always {@code 0}. */
  @Override
  public long misses() {
    return 0;
  }

  /** Indicates if a key is probably present; always returns {@code false}. */
  @Override
  public boolean probablyInStore(byte[] routingKey) {
    return false;
  }

  /**
   * Accepts a put request but performs no write.
   *
   * <p>All parameters are ignored; the store remains empty regardless of {@code overwrite} or
   * {@code oldBlock} flags.
   *
   * @param block the block descriptor; ignored
   * @param data the block payload; ignored
   * @param header the block header; ignored
   * @param overwrite whether existing data may be overwritten; ignored
   * @param oldBlock whether the block is considered old; ignored
   * @throws IOException never thrown by this implementation
   * @throws KeyCollisionException never thrown by this implementation
   */
  @Override
  public void put(T block, byte[] data, byte[] header, boolean overwrite, boolean oldBlock)
      throws IOException, KeyCollisionException {
    // No-op: the null store does not persist data.
  }

  /**
   * Sets a maximum key count, ignored by this implementation.
   *
   * @param maxStoreKeys desired capacity; ignored
   * @param shrinkNow whether to shrink immediately; ignored
   * @throws IOException never thrown by this implementation
   */
  @Override
  public void setMaxKeys(long maxStoreKeys, boolean shrinkNow) throws IOException {
    // No-op: capacity and compaction are not applicable.
  }

  /** Returns the number of writes performed, always {@code 0}. */
  @Override
  public long writes() {
    return 0;
  }

  /**
   * Returns access statistics for the current session.
   *
   * <p>The returned {@link StoreAccessStats} instance reports all counters as {@code 0}.
   *
   * @return a stats view whose values are always {@code 0}
   */
  @Override
  public StoreAccessStats getSessionAccessStats() {
    return new StoreAccessStats() {

      @Override
      public long hits() {
        return 0;
      }

      @Override
      public long misses() {
        return 0;
      }

      @Override
      public long falsePos() {
        return 0;
      }

      @Override
      public long writes() {
        return 0;
      }
    };
  }

  /**
   * Returns cumulative access statistics.
   *
   * <p>Because the null store does not track totals, this method returns {@code null}. Callers
   * should handle a {@code null} response to mean “not available”.
   *
   * @return always {@code null}
   */
  @Override
  public StoreAccessStats getTotalAccessStats() {
    return null;
  }

  /**
   * Starts the store, always returning {@code false} to indicate no background work is performed.
   *
   * @param ticker periodic task runner; ignored
   * @param longStart whether a long start path is requested; ignored
   * @return always {@code false}
   * @throws IOException never thrown by this implementation
   */
  @Override
  public boolean start(Ticker ticker, boolean longStart) throws IOException {
    return false;
  }

  /** Sets a store alert sink; ignored because the store has no alerts to raise. */
  @Override
  public void setStoreAlertSink(StoreAlertSink alertSink) {
    // No-op
  }

  /** Returns this instance as the underlying store. */
  @Override
  public FreenetStore<T> getUnderlyingStore() {
    return this;
  }

  /** Closes the store; no resources are held, so this is a no-op. */
  @Override
  public void close() {
    // No-op
  }
}

package network.crypta.store;

import java.io.Closeable;
import java.io.IOException;
import network.crypta.node.stats.StoreAccessStats;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.Ticker;

/**
 * Common interface for Crypta's key–value block stores.
 *
 * <p>Implementations persist or cache {@link StorableBlock} instances keyed by their routing key
 * (and, when required by the block type, the full key). Stores may be in‑memory, on‑disk, or
 * wrappers around other stores. Concurrency semantics, persistence guarantees, and background
 * maintenance vary by implementation; callers should not assume additional behavior beyond what is
 * documented here.
 *
 * @param <T> concrete block type stored by this instance
 */
public interface FreenetStore<T extends StorableBlock> extends Closeable {

  /**
   * Retrieve a block by routing key.
   *
   * <p>Implementations may use {@code fullKey} during reconstruction or verification. When {@code
   * dontPromote} is {@code true}, the access does not affect recency ordering in LRU-based stores.
   * If {@code ignoreOldBlocks} is {@code true}, blocks marked as "old" are treated as not present.
   * When {@code meta} is non-null, implementations may populate it (for example, to report whether
   * the block is considered old).
   *
   * @param routingKey non-null routing key used to locate the entry.
   * @param fullKey optional full key; may be {@code null} for block types that do not require it.
   * @param dontPromote when {@code true}, do not promote the entry in any recency structure.
   * @param canReadClientCache whether lookups may consult the client cache (e.g., to get SSK public
   *     keys).
   * @param canReadSlashdotCache whether lookups may consult the Slashdot cache when resolving
   *     prerequisites such as public keys.
   * @param ignoreOldBlocks when {@code true}, suppress returning blocks flagged as old.
   * @param meta optional metadata sink to be filled by the implementation; may be {@code null}.
   * @return the block instance, or {@code null} if not found (or filtered by {@code
   *     ignoreOldBlocks}).
   * @throws IOException on I/O errors encountered during the operation.
   */
  T fetch(
      byte[] routingKey,
      byte[] fullKey,
      boolean dontPromote,
      boolean canReadClientCache,
      boolean canReadSlashdotCache,
      boolean ignoreOldBlocks,
      BlockMetadata meta)
      throws IOException;

  /**
   * Retrieve a block by the routing key with a parameter object.
   *
   * <p>The default implementation delegates to {@link #fetch(byte[], byte[], boolean, boolean,
   * boolean, boolean, BlockMetadata)} using values from {@code options}.
   *
   * @param routingKey non-null routing key used to locate the entry.
   * @param fullKey optional full key; may be {@code null} for block types that do not require it.
   * @param options grouped fetch options; must not be {@code null}.
   * @return the block instance, or {@code null} if not found.
   * @throws IOException on I/O errors encountered during the operation.
   */
  default T fetch(byte[] routingKey, byte[] fullKey, FetchOptions options) throws IOException {
    if (options == null) {
      throw new IllegalArgumentException("options must not be null");
    }
    return fetch(
        routingKey,
        fullKey,
        options.dontPromote(),
        options.canReadClientCache(),
        options.canReadSlashdotCache(),
        options.ignoreOldBlocks(),
        options.meta());
  }

  /**
   * Store a block.
   *
   * <p>Implementations persist {@code data} and {@code header} under {@code block}'s key. When
   * {@code overwrite} is {@code false} and an entry with a different value already exists for the
   * same key, a {@link KeyCollisionException} may be thrown. When {@code oldBlock} is {@code true},
   * the block is marked so that it is not proactively advertised or shared via probabilistic
   * filters; this status may be reported later via {@link BlockMetadata} when fetching.
   *
   * @param block logical block providing keys.
   * @param data raw block payload to store.
   * @param header raw header bytes to store; may be empty when not used by the block type.
   * @param overwrite when {@code true}, replace any existing content for the key.
   * @param oldBlock when {@code true}, record the block as "old" for downstream logic.
   * @throws IOException on I/O errors.
   * @throws KeyCollisionException if an entry exists for the key and overwriting is disallowed.
   */
  void put(T block, byte[] data, byte[] header, boolean overwrite, boolean oldBlock)
      throws IOException, KeyCollisionException;

  /**
   * Change the store capacity.
   *
   * <p>Adjust the maximum number of keys the store retains. Implementations may perform expensive
   * maintenance when shrinking; if {@code shrinkNow} is {@code false}, the implementation may defer
   * compaction/eviction while still honoring the new limit for later operations.
   *
   * @param maxStoreKeys new maximum number of keys the store may hold.
   * @param shrinkNow when {@code true}, perform any required shrinking immediately if possible.
   * @throws IOException on configuration persistence or resize failures.
   */
  void setMaxKeys(long maxStoreKeys, boolean shrinkNow) throws IOException;

  /**
   * Return the configured maximum number of keys.
   *
   * @return current capacity limit as a number of keys.
   */
  long getMaxKeys();

  /**
   * Return the number of successful fetches served by this store.
   *
   * @return count of read hits.
   */
  long hits();

  /**
   * Return the number of failed lookups.
   *
   * @return count of read misses.
   */
  long misses();

  /**
   * Return the number of writing attempts accepted by this store.
   *
   * @return count of {@link #put} operations.
   */
  long writes();

  /**
   * Return the current number of keys stored.
   *
   * @return live key count.
   */
  long keyCount();

  /**
   * Return the number of false positives reported by any probabilistic membership pre-check used by
   * the store (for example, a Bloom or slot filter).
   *
   * <p>Value semantics are implementation-specific; a non-negative value typically represents a
   * cumulative count.
   *
   * @return recorded false positives; implementations that do not track this may return an
   *     implementation-defined sentinel.
   */
  long getBloomFalsePositive();

  /**
   * Test whether a routing key is probably present.
   *
   * <p>This is a fast pre-check intended to avoid unnecessary I/O. The result may be a false
   * positive; negative results are definitive.
   *
   * @param routingKey non-null routing key to test.
   * @return {@code false} only if the key definitely does not exist; {@code true} otherwise.
   */
  boolean probablyInStore(byte[] routingKey);

  /**
   * Per-session access statistics since the current store instance started.
   *
   * @return a non-null snapshot of recent access statistics.
   */
  StoreAccessStats getSessionAccessStats();

  /**
   * Lifetime access statistics aggregated across sessions, when available.
   *
   * @return a snapshot of long-term statistics, or {@code null} if unsupported.
   */
  StoreAccessStats getTotalAccessStats();

  /**
   * Initialize the store and perform any deferred work.
   *
   * <p>Implementations may use {@code ticker} for cooperative progress or time budgeting. When
   * {@code longStart} is {@code true}, the caller permits longer initialization (e.g., rebuilding
   * auxiliary structures).
   *
   * @param ticker implementations; may ignore progress/heartbeat helper.
   * @param longStart whether long-running initialization is permitted.
   * @return {@code true} if initialization completed; {@code false} otherwise.
   * @throws IOException on initialization failure.
   */
  boolean start(Ticker ticker, boolean longStart) throws IOException;

  /** Close the store and release resources. */
  @Override
  void close();

  /**
   * Set the user alert manager used to publish non-fatal warnings and notices related to the store
   * (for example, background rebuild progress or recoverable errors).
   *
   * @param userAlertManager manager used to post user-facing alerts; may be ignored by some
   *     implementations.
   */
  void setUserAlertManager(UserAlertManager userAlertManager);

  /**
   * Return the underlying store when this instance is a wrapper.
   *
   * <p>For composite stores, returns the direct delegate that actually performs operations. For
   * concrete stores, this method typically returns {@code this}.
   *
   * @return the underlying concrete store.
   */
  FreenetStore<T> getUnderlyingStore();
}

package network.crypta.store;

import java.io.IOException;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.keys.KeyVerifyException;
import network.crypta.node.stats.StoreAccessStats;
import org.jetbrains.annotations.NotNull;

/**
 * Adapts a concrete block type for use by a {@link FreenetStore}.
 *
 * <p>A {@code StoreCallback} supplies the datastore with the fixed sizes for block data, headers,
 * routing keys, and full keys, and it translates raw byte arrays into a {@link StorableBlock}
 * instance during fetch. Callers typically create one callback per block family (such as CHK or
 * SSK) and bind it to a store using {@link #setStore(FreenetStore)}. The callback may be reused
 * across wrapper stores, and the most recent {@code setStore} call becomes the active delegate for
 * accessors like {@link #hits()} or {@link #getSessionAccessStats()}.
 *
 * <p>Implementations should treat the callback as a lightweight policy object rather than a storage
 * container. The instance usually holds minimal mutable state, but it does retain a reference to
 * the current store, so it is not inherently thread-safe without external synchronization. Most
 * getters are simple delegations; consequently, callers should avoid assuming cached values when
 * they mutate the underlying store configuration. Unless otherwise stated, byte arrays returned
 * from callback methods or constructed blocks should be treated as read-only views and may share
 * backing buffers for efficiency.
 *
 * <ul>
 *   <li>Defines the fixed byte lengths used for store layout and validation.
 *   <li>Constructs {@link StorableBlock} instances from persisted bytes and metadata.
 *   <li>Converts between routing keys and full keys for lookups.
 * </ul>
 *
 * @param <T> concrete block type handled by this callback implementation.
 * @author toad
 */
public abstract class StoreCallback<T extends StorableBlock> {

  /**
   * Creates a new callback instance with no bound store.
   *
   * <p>The constructor performs no initialization beyond the default field values. Callers are
   * expected to bind a store using {@link #setStore(FreenetStore)} before invoking delegation
   * methods. Subclasses may add their own initialization logic while still respecting the contract
   * that the callback starts unbound.
   */
  protected StoreCallback() {}

  /**
   * Returns the length in bytes of the data section for this block type.
   *
   * <p>This value is fixed for a given callback implementation and should not change after the
   * callback is bound to a store. Stores use it to size buffers, validate payload lengths, and
   * compute on-disk record layouts. Callers may cache the result, but they should treat it as an
   * invariant of the block type rather than a mutable configuration value.
   *
   * @return the immutable payload length in bytes for this block type.
   */
  public abstract int dataLength();

  /**
   * Returns the length in bytes of the header section for this block type.
   *
   * <p>The header length is fixed for the block family and remains constant for the lifetime of any
   * store using this callback. Stores rely on this size to allocate header buffers and validate
   * persisted records. Implementations should return a non-negative value that matches the layout
   * expected by {@link StorableBlock} reconstruction.
   *
   * @return the immutable header length in bytes for this block type.
   */
  public abstract int headerLength();

  /**
   * Returns the length in bytes of the routing key used for lookups in the datastore.
   *
   * <p>The routing key length is fixed for the block type. It must match the arrays produced by
   * {@link #routingKeyFromFullKey(byte[])} and returned by {@link StorableBlock#getRoutingKey()}.
   * Stores use this value to normalize lookups and to validate that keys provided by callers have
   * the expected size before hashing or indexing.
   *
   * @return the immutable routing key length in bytes for this block type.
   */
  public abstract int routingKeyLength();

  /**
   * Indicates whether the store should persist full keys in a sidecar file (typically {@code
   * .keys}).
   *
   * <p>When {@code true}, the store writes the full key for each entry so blocks can be
   * reconstructed or validated without recomputing it from the payload. This setting influences
   * disk usage and enables operations that need the original full key later in the lifecycle, such
   * as certain verification or migration flows. See {@link #fullKeyLength()} for the expected size
   * when full keys are stored.
   *
   * @return {@code true} when full keys must be persisted alongside stored blocks.
   */
  public abstract boolean storeFullKeys();

  /**
   * Indicates whether reconstruction requires key material.
   *
   * <p>When {@code true}, callers must supply either the routing key or the full key (or both) in
   * {@link BlockPayload} when calling {@link #construct(BlockPayload, ConstructOptions,
   * DSAPublicKey)}. Implementations that can reconstruct blocks without key material may return
   * {@code false}, which allows store callers to omit missing keys when retrieving data from
   * alternate sources. The value should remain stable for a given callback instance.
   *
   * @return {@code true} if key material is required to construct a block instance.
   */
  @SuppressWarnings("unused")
  public abstract boolean constructNeedsKey();

  /**
   * Returns the length in bytes of the full key for this block type.
   *
   * <p>The full key length is fixed for the block family and is used when persisting to or reading
   * from the optional {@code .keys} file. Implementations should return a non-negative size that
   * matches the serialized full key layout used by the corresponding {@link StorableBlock}.
   *
   * @return the immutable full key length in bytes for this block type.
   */
  public abstract int fullKeyLength();

  /**
   * Reports whether two different blocks can legitimately share the same key.
   *
   * <p>If {@code true}, the store must treat duplicate keys as potential collisions and may throw
   * {@link KeyCollisionException} on insert unless explicitly told to overwrite. If {@code false},
   * a duplicate key implies identical content for this block type, allowing the store to keep the
   * first copy without additional checks. The result should reflect the block format's collision
   * semantics and remain constant for the callback's lifetime.
   *
   * @return {@code true} if key collisions between distinct blocks are possible.
   */
  public abstract boolean collisionPossible();

  /**
   * Store currently associated with this callback and used for delegation.
   *
   * <p>This reference is assigned by {@link #setStore(FreenetStore)} and accessed by convenience
   * methods such as {@link #hits()} and {@link #setMaxKeys(long, boolean)}. It is mutable and not
   * inherently thread-safe; callers should coordinate access if the callback is shared across
   * threads that rebind the store.
   */
  protected FreenetStore<T> store;

  /**
   * Binds this callback to a {@link FreenetStore} instance.
   *
   * <p>This method configures the store used by delegation methods such as {@link #hits()} and
   * {@link #setMaxKeys(long, boolean)}. If the provided store is a wrapper, the callback may be
   * re-bound multiple times as the wrapper stack is assembled; the most recent call determines the
   * effective target. Callers should ensure they publish the updated callback to all threads that
   * will use it, because this mutation is not synchronized.
   *
   * @param store target store to associate with this callback; must not be {@code null}.
   */
  public void setStore(FreenetStore<T> store) {
    this.store = store;
  }

  /**
   * Returns the store currently associated with this callback.
   *
   * <p>The returned reference is the most recent value supplied to {@link #setStore(FreenetStore)}.
   * Callers should treat the result as a mutable shared state and avoid assuming it is constant
   * across threads or over time.
   *
   * @return the bound {@link FreenetStore}, or {@code null} if uninitialized.
   */
  public FreenetStore<T> getStore() {
    return store;
  }

  // Reconstruction entry point

  /**
   * Packages raw block bytes and optional key material for reconstruction.
   *
   * <p>This record is a value carrier used when constructing blocks via {@link
   * #construct(BlockPayload, ConstructOptions, DSAPublicKey)}. The byte arrays are not defensively
   * copied; callers should treat them as read-only views of store buffers or caller-managed byte
   * arrays. Implementations may accept {@code null} for {@code routingKey} or {@code fullKey} when
   * the key material is unavailable, but they should enforce their own preconditions by throwing
   * {@link KeyVerifyException} as needed.
   *
   * @param data raw payload bytes of length {@link #dataLength()}; may be {@code null} if
   *     reconstruction is expected to fail fast.
   * @param headers raw header bytes of length {@link #headerLength()}; may be {@code null} if the
   *     implementation validates presence at construction time.
   * @param routingKey routing key bytes, or {@code null} when unavailable or not required.
   * @param fullKey full key bytes, or {@code null} when unavailable or not required.
   */
  public record BlockPayload(byte[] data, byte[] headers, byte[] routingKey, byte[] fullKey) {
    /**
     * Compares payloads by array contents rather than reference identity.
     *
     * <p>The comparison is null-safe and uses {@link java.util.Arrays#equals(byte[], byte[])} for
     * each array field. This ensures two payloads with identical bytes are treated as equal even if
     * they point at different buffers.
     *
     * @param obj the object to compare with this payload instance.
     * @return {@code true} when all array fields are equal by content.
     */
    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (!(obj
          instanceof
          BlockPayload(
              byte[] otherData,
              byte[] otherHeaders,
              byte[] otherRoutingKey,
              byte[] otherFullKey))) {
        return false;
      }
      return java.util.Arrays.equals(data, otherData)
          && java.util.Arrays.equals(headers, otherHeaders)
          && java.util.Arrays.equals(routingKey, otherRoutingKey)
          && java.util.Arrays.equals(fullKey, otherFullKey);
    }

    /**
     * Computes a hash code based on the contents of the byte array fields.
     *
     * <p>The hash combines {@link java.util.Arrays#hashCode(byte[])} for each field so it remains
     * consistent with {@link #equals(Object)} for content-based comparisons.
     *
     * @return a hash derived from the payload byte contents.
     */
    @Override
    public int hashCode() {
      int result = java.util.Arrays.hashCode(data);
      result = 31 * result + java.util.Arrays.hashCode(headers);
      result = 31 * result + java.util.Arrays.hashCode(routingKey);
      result = 31 * result + java.util.Arrays.hashCode(fullKey);
      return result;
    }

    /**
     * Returns a human-readable representation of the payload contents.
     *
     * <p>The string renders each byte array using {@link java.util.Arrays#toString(byte[])} and is
     * intended for debugging and logging rather than stable serialization.
     *
     * @return a string containing the array contents for inspection.
     */
    @Override
    public @NotNull String toString() {
      return "BlockPayload{data="
          + java.util.Arrays.toString(data)
          + ", headers="
          + java.util.Arrays.toString(headers)
          + ", routingKey="
          + java.util.Arrays.toString(routingKey)
          + ", fullKey="
          + java.util.Arrays.toString(fullKey)
          + "}";
    }
  }

  /**
   * Groups cache access flags and metadata passed during reconstruction.
   *
   * <p>This record carries fetch-time context used by {@link #construct(BlockPayload,
   * ConstructOptions, DSAPublicKey)} implementations. The boolean flags tell implementations
   * whether they may consult client or slashdot caches, while {@code meta} carries store-provided
   * metadata such as old-block markers or caller-specific hints. The record is immutable and may be
   * reused across multiple reconstruction calls for the same fetch operation.
   *
   * @param canReadClientCache {@code true} when client cache reads are permitted for this fetch.
   * @param canReadSlashdotCache {@code true} when slashdot cache reads are permitted for this
   *     fetch.
   * @param meta metadata collected during the fetch; may be {@code null} if unused.
   */
  public record ConstructOptions(
      boolean canReadClientCache, boolean canReadSlashdotCache, BlockMetadata meta) {}

  /**
   * Constructs a block instance from raw data and headers, with optional key material.
   *
   * <p>This is the primary reconstruction hook used by {@link FreenetStore} implementations when
   * loading blocks from disk or cache. Implementations should validate the supplied bytes, enforce
   * any required key material, and either return a fully verified {@link StorableBlock} or throw a
   * {@link KeyVerifyException}. The method should be free of side effects beyond the reconstruction
   * itself, so callers can safely retry or fallback. If a key is supplied but not required, it is
   * not validated here; callers remain responsible for ensuring the constructed block matches the
   * expected key.
   *
   * <p>Implementations should assume the input arrays may be shared buffers and must not mutate
   * them. When {@code knownPubKey} is provided, implementations may bypass key lookup logic, but
   * they should still validate any signatures or bindings implied by the block format.
   *
   * @param payload raw payload, headers, and optional key material for reconstruction; may contain
   *     {@code null} keys depending on {@link #constructNeedsKey()}.
   * @param options cache flags and metadata that guide cache lookups and reconstruction decisions.
   * @param knownPubKey optional public key information supplied by the caller; may be {@code null}.
   * @return a newly constructed block instance, ready for use by the caller.
   * @throws KeyVerifyException if required data is missing or validation fails during
   *     reconstruction.
   */
  public abstract T construct(
      BlockPayload payload, ConstructOptions options, DSAPublicKey knownPubKey)
      throws KeyVerifyException;

  /**
   * Sets the maximum number of keys the associated store should keep.
   *
   * <p>This convenience method delegates to {@link FreenetStore#setMaxKeys(long, boolean)} on the
   * bound store. Implementations typically enforce the new limit lazily; when {@code shrinkNow} is
   * {@code true}, the store may attempt to evict entries immediately. Callers should treat this as
   * a potentially expensive operation that can trigger disk I/O and eviction work.
   *
   * @param maxStoreKeys new capacity in keys; must be non-negative for most implementations.
   * @param shrinkNow {@code true} to request immediate shrinking when supported by the store.
   * @throws IOException if the underlying store reports an I/O error while resizing.
   */
  public void setMaxKeys(long maxStoreKeys, boolean shrinkNow) throws IOException {
    store.setMaxKeys(maxStoreKeys, shrinkNow);
  }

  /**
   * Returns the configured key capacity from the underlying store.
   *
   * <p>The returned value reflects the store's current configuration and may change if {@link
   * #setMaxKeys(long, boolean)} is called. Callers should not assume the value is cached in the
   * callback; it is fetched from the underlying store each time.
   *
   * @return the maximum number of keys the store is configured to keep.
   */
  public long getMaxKeys() {
    return store.getMaxKeys();
  }

  /**
   * Returns the number of successful lookups reported by the underlying store.
   *
   * <p>This counter typically increases when {@link FreenetStore#fetch(byte[], byte[], boolean,
   * boolean, boolean, boolean, BlockMetadata)} returns a block. It is intended for monitoring and
   * does not reset automatically between sessions unless the store implementation does so.
   *
   * @return the number of successful lookup operations recorded by the store.
   */
  public long hits() {
    return store.hits();
  }

  /**
   * Returns the number of failed lookups reported by the underlying store.
   *
   * <p>This counter increases when a lookup fails due to missing data or verification failures,
   * depending on store policy. It is useful for tracking cache hit rates and eviction behavior.
   *
   * @return the number of failed lookup operations recorded by the store.
   */
  public long misses() {
    return store.misses();
  }

  /**
   * Returns the number of completed writes reported by the underlying store.
   *
   * <p>The value typically increments when a {@link FreenetStore#put(StorableBlock, byte[], byte[],
   * boolean, boolean)} completes successfully. It can be used alongside {@link #hits()} and {@link
   * #misses()} to estimate workload patterns.
   *
   * @return the number of write operations recorded by the store.
   */
  public long writes() {
    return store.writes();
  }

  /**
   * Returns the current number of keys tracked by the underlying store.
   *
   * <p>Implementations may return an approximate count when the store is large or uses
   * probabilistic structures. The value can change rapidly as keys are added or evicted.
   *
   * @return the current number of keys tracked by the store.
   */
  public long keyCount() {
    return store.keyCount();
  }

  /**
   * Returns the false-positive count reported by the store's Bloom filter, if available.
   *
   * <p>Some stores track Bloom filter false positives for diagnostics. When unsupported, the store
   * may return a sentinel value such as {@code -1}. Callers should treat the value as a best-effort
   * diagnostic rather than a precise metric.
   *
   * @return the Bloom filter false-positive count or a sentinel value if unsupported.
   */
  public long getBloomFalsePositive() {
    return store.getBloomFalsePositive();
  }

  /**
   * Computes the routing key corresponding to a given full key.
   *
   * <p>This method provides the inverse of full-key generation for lookup operations. The returned
   * array's length equals {@link #routingKeyLength()}, and callers should treat the result as
   * read-only. Implementations may return a newly allocated array or a view onto an internal
   * buffer, so callers must not mutate the returned bytes.
   *
   * @param keyBuf full key bytes whose length should match {@link #fullKeyLength()}; must not be
   *     {@code null} for valid conversion.
   * @return routing key bytes derived from {@code keyBuf} for datastore lookups.
   */
  @SuppressWarnings("unused")
  public abstract byte[] routingKeyFromFullKey(byte[] keyBuf);

  /**
   * Returns per-session access statistics from the underlying store.
   *
   * <p>The returned {@link StoreAccessStats} instance tracks counters that reset when the store
   * restarts or when a new stats object is allocated. Use this to report short-term hit/miss trends
   * without mixing data across restarts.
   *
   * @return a {@link StoreAccessStats} snapshot for the current session.
   */
  public StoreAccessStats getSessionAccessStats() {
    return store.getSessionAccessStats();
  }

  /**
   * Returns overall access statistics across sessions when supported by the store.
   *
   * <p>Some implementations persist these counters across restarts to provide long-term metrics.
   * When unsupported, {@code null} is returned and callers should fall back to {@link
   * #getSessionAccessStats()}. The datastore may not persist uptime, so callers can combine the
   * stats with their own uptime accounting when needed.
   *
   * @return the cumulative stats object, or {@code null} if unsupported by the store.
   */
  public StoreAccessStats getTotalAccessStats() {
    return store.getTotalAccessStats();
  }

  /**
   * Returns the total in-memory size of a block including data, headers, full key, and routing key.
   *
   * <p>This convenience method sums the fixed lengths reported by {@link #dataLength()}, {@link
   * #headerLength()}, {@link #fullKeyLength()}, and {@link #routingKeyLength()}. It is useful for
   * estimating cache or buffer sizes, but it does not account for object headers or per-entry
   * metadata in store implementations.
   *
   * @return total size in bytes for a single block payload and its keys.
   */
  public int getTotalBlockSize() {
    return dataLength() + headerLength() + fullKeyLength() + routingKeyLength();
  }
}

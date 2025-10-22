package network.crypta.store;

import java.io.IOException;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.keys.KeyVerifyException;
import network.crypta.node.stats.StoreAccessStats;

/**
 * Strategy interface that adapts a concrete block type to a {@link FreenetStore}.
 *
 * <p>A {@code StoreCallback} defines the fixed sizes for data, headers, routing keys, and full keys
 * for a particular block type; it constructs a {@link StorableBlock} from raw bytes when fetching;
 * and it provides conversions between full and routing keys. An instance is typically bound to a
 * store via {@link #setStore(FreenetStore)} and may be reused with store wrappers; the last call to
 * {@code setStore} determines the active target.
 *
 * <p>Unless otherwise stated, returned byte arrays should be treated as read-only. Implementations
 * may return internal buffers for efficiency.
 *
 * @param <T> block type handled by this callback.
 * @author toad
 */
public abstract class StoreCallback<T extends StorableBlock> {

  /**
   * Returns the length in bytes of the data section for this block type.
   *
   * <p>The value is constant for the lifetime of the associated store and is used for buffer
   * allocation and on-disk layout.
   *
   * @return data length in bytes.
   */
  public abstract int dataLength();

  /**
   * Returns the length in bytes of the header section for this block type.
   *
   * <p>The value is constant for the lifetime of the associated store.
   *
   * @return header length in bytes.
   */
  public abstract int headerLength();

  /**
   * Returns the length in bytes of the routing key used for lookups in the datastore.
   *
   * <p>The routing key length is fixed and must match the arrays produced by {@link
   * #routingKeyFromFullKey(byte[])} and returned by {@link StorableBlock#getRoutingKey()}.
   *
   * @return routing key length in bytes.
   */
  public abstract int routingKeyLength();

  /**
   * Indicates whether the store should persist full keys in a sidecar file (typically {@code
   * .keys}).
   *
   * <p>When {@code true}, the store writes the full key for each entry so blocks can be
   * reconstructed or validated without recomputing it from the payload. See {@link
   * #fullKeyLength()} for the expected size.
   *
   * @return {@code true} if full keys are persisted.
   */
  public abstract boolean storeFullKeys();

  /**
   * Indicates whether reconstruction requires the key material.
   *
   * <p>When {@code true}, callers must supply either the routing key or the full key (or both) to
   * {@link #construct(byte[], byte[], byte[], byte[], boolean, boolean, BlockMetadata,
   * DSAPublicKey)}.
   *
   * @return {@code true} if a key is required to construct a block instance.
   */
  @SuppressWarnings("unused")
  public abstract boolean constructNeedsKey();

  /**
   * Returns the length in bytes of the full key for this block type.
   *
   * <p>The value is fixed and is used when persisting to/reading from the optional {@code .keys}
   * file.
   *
   * @return full key length in bytes.
   */
  public abstract int fullKeyLength();

  /**
   * Reports whether two different blocks can legitimately share the same key.
   *
   * <p>If {@code true}, stores may throw {@link KeyCollisionException} on insert unless explicitly
   * told to overwrite. If {@code false}, a duplicate key implies identical content for this block
   * type.
   *
   * @return {@code true} if key collisions between distinct blocks are possible.
   */
  public abstract boolean collisionPossible();

  /** Store currently associated with this callback and used for delegation. */
  protected FreenetStore<T> store;

  /**
   * Binds this callback to a {@link FreenetStore} instance.
   *
   * <p>If the provided store is a wrapper, this method may be called multiple times; the most
   * recent call determines the effective store used by delegation methods.
   *
   * @param store target store to associate with this callback.
   */
  public void setStore(FreenetStore<T> store) {
    this.store = store;
  }

  /**
   * Returns the store currently associated with this callback.
   *
   * @return the bound {@link FreenetStore}.
   */
  public FreenetStore<T> getStore() {
    return store;
  }

  // Reconstruction entry point

  /**
   * Constructs a block instance from raw data and headers, with optional key material.
   *
   * <p>Supplying {@code routingKey} or {@code fullKey} is optional and used only when required by
   * the implementation. If a key is provided but not used, it is not validated here; the caller is
   * responsible for checking that the resulting block matches the expected key.
   *
   * @param data raw payload bytes of length {@link #dataLength()}.
   * @param headers raw header bytes of length {@link #headerLength()}.
   * @param routingKey routing key bytes or {@code null} if unavailable.
   * @param fullKey full key bytes or {@code null} if unavailable.
   * @param canReadClientCache whether the client cache may be read during reconstruction.
   * @param canReadSlashdotCache whether the slashdot cache may be read during reconstruction.
   * @param meta metadata collected during fetch; may be used to guide reconstruction.
   * @param knownPubKey optional known public key information (e.g., for SSK).
   * @return a newly constructed block instance.
   * @throws KeyVerifyException if integrity or signature checks fail during reconstruction.
   */
  public abstract T construct(
      byte[] data,
      byte[] headers,
      byte[] routingKey,
      byte[] fullKey,
      boolean canReadClientCache,
      boolean canReadSlashdotCache,
      BlockMetadata meta,
      DSAPublicKey knownPubKey)
      throws KeyVerifyException;

  /**
   * Sets the maximum number of keys the associated store should keep.
   *
   * <p>Delegates to {@link FreenetStore#setMaxKeys(long, boolean)} on the bound store.
   *
   * @param maxStoreKeys new capacity in keys.
   * @param shrinkNow if {@code true}, requests an immediate shrink when supported by the store.
   * @throws IOException if the underlying store reports an I/O error.
   */
  public void setMaxKeys(long maxStoreKeys, boolean shrinkNow) throws IOException {
    store.setMaxKeys(maxStoreKeys, shrinkNow);
  }

  /** Returns the configured key capacity from the underlying store. */
  public long getMaxKeys() {
    return store.getMaxKeys();
  }

  /** Returns the number of successful lookups reported by the underlying store. */
  public long hits() {
    return store.hits();
  }

  /** Returns the number of failed lookups reported by the underlying store. */
  public long misses() {
    return store.misses();
  }

  /** Returns the number of completed writes reported by the underlying store. */
  public long writes() {
    return store.writes();
  }

  /** Returns the current number of keys tracked by the underlying store. */
  public long keyCount() {
    return store.keyCount();
  }

  /** Returns the false-positive count reported by the store's Bloom filter, if available. */
  public long getBloomFalsePositive() {
    return store.getBloomFalsePositive();
  }

  /**
   * Computes the routing key corresponding to a given full key.
   *
   * <p>The returned array's length equals {@link #routingKeyLength()}.
   *
   * @param keyBuf full key bytes.
   * @return routing key bytes derived from {@code keyBuf}.
   */
  @SuppressWarnings("unused")
  public abstract byte[] routingKeyFromFullKey(byte[] keyBuf);

  /**
   * Returns per-session access statistics from the underlying store.
   *
   * @return a {@link StoreAccessStats} instance.
   */
  public StoreAccessStats getSessionAccessStats() {
    return store.getSessionAccessStats();
  }

  /**
   * Returns overall access statistics across sessions when supported by the store.
   *
   * <p>The datastore may not persist uptime; callers can combine this with their own uptime
   * accounting when needed.
   *
   * @return the stats object, or {@code null} if unsupported by the store.
   */
  public StoreAccessStats getTotalAccessStats() {
    return store.getTotalAccessStats();
  }

  /**
   * Returns the total in-memory size of a block including data, headers, full key, and routing key.
   *
   * @return total size in bytes.
   */
  public int getTotalBlockSize() {
    return dataLength() + headerLength() + fullKeyLength() + routingKeyLength();
  }
}

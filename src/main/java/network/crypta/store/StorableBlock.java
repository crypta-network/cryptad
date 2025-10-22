package network.crypta.store;

/**
 * Minimal contract for a block that can be persisted in a {@link FreenetStore}.
 *
 * <p>Implementations expose two opaque identifiers:
 *
 * <ul>
 *   <li><b>Routing key</b> — used as the datastore lookup key and for Bloom/probability checks. Its
 *       length is defined by the associated {@link StoreCallback#routingKeyLength()} and the format
 *       is implementation-specific.
 *   <li><b>Full key</b> — a canonical identifier for the exact block instance. When the store is
 *       configured to keep full keys (see {@link StoreCallback#storeFullKeys()}), this value is
 *       written to the optional <em>.keys</em> side file to allow reconstruction and collision
 *       checks.
 * </ul>
 *
 * <p>Neither key's contents or encoding are prescribed by this interface. Callers must treat the
 * returned arrays as read-only; implementations may return internal buffers for efficiency.
 */
public interface StorableBlock {

  /**
   * Returns the routing key used to locate this block within a datastore.
   *
   * <p>The value is opaque to callers. Its size should match {@link
   * StoreCallback#routingKeyLength()}. The returned array may be an internal buffer and must be
   * treated as read-only; copy it if you need to retain or mutate it.
   *
   * @return byte array representing the routing key.
   */
  byte[] getRoutingKey();

  /**
   * Returns the full key that uniquely identifies this block instance.
   *
   * <p>The full key can be stored alongside data for reconstruction and validation when enabled by
   * {@link StoreCallback#storeFullKeys()}. Its size should match {@link
   * StoreCallback#fullKeyLength()}. Implementations may return the same bytes as {@link
   * #getRoutingKey()} when both identifiers are equivalent for the block type. The returned array
   * must be treated as read-only.
   *
   * @return byte array representing the full key.
   */
  byte[] getFullKey();
}

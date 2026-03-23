package network.crypta.store;

/**
 * Minimal contract for a block that can be addressed by store code.
 *
 * <p>Implementations expose two opaque identifiers:
 *
 * <ul>
 *   <li>A routing key used for lookups and indexing.
 *   <li>A full key that identifies the exact serialized block instance.
 * </ul>
 *
 * <p>Neither identifier's encoding is prescribed here. Callers must treat returned arrays as
 * read-only; implementations may return internal buffers.
 */
public interface StorableBlock {

  /**
   * Returns the routing key used to locate this block.
   *
   * @return opaque routing-key bytes
   */
  byte[] getRoutingKey();

  /**
   * Returns the full key that uniquely identifies this block instance.
   *
   * @return opaque full-key bytes
   */
  byte[] getFullKey();
}

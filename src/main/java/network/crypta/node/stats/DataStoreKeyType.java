package network.crypta.node.stats;

/**
 * Categorizes the logical key type used by a data store.
 *
 * <p>This enumeration is used by the node statistics and diagnostics code to tag metrics and
 * counters with the kind of key a particular store operates on. Some stores persist entries
 * addressed by content-derived hashes, while others group entries under keys associated with
 * signing or publishing identities. Consumers of {@code network.crypta.node.stats} can use this
 * type to render human-readable labels, aggregate metrics by key family, or switch behavior when a
 * feature applies only to a subset of key kinds.
 *
 * <p>The values are intentionally high level and stable. They abstract over any on-disk
 * representation or wire format and do not prescribe a specific encoding or bit length. The enum is
 * immutable and thread-safe; it carries no state beyond the constant identity and can be freely
 * shared between threads without synchronization.
 *
 * <ul>
 *   <li>{@link #CHK} — keys derived from the content itself (content-addressed).
 *   <li>{@link #SSK} — keys associated with signed/identity-scoped data.
 *   <li>{@link #PUB_KEY} — keys that directly refer to public keys or key material.
 * </ul>
 *
 * @see network.crypta.node.stats.DataStoreType
 * @see network.crypta.node.stats.DataStoreStats
 */
public enum DataStoreKeyType {
  /**
   * Content-addressed key type used for stores where the key is derived from the data.
   *
   * <p>Entries indexed under this category are typically immutable and retrievable by providing a
   * hash or similar content-derived identifier. This is a good default for caches, chunk stores, or
   * other structures where the identity of the content is sufficient to locate and validate the
   * record. Reporting that references this constant usually assumes read-mostly access patterns and
   * high deduplication potential.
   */
  CHK,

  /**
   * Signed or identity-scoped key type used for stores that group data under a signing identity.
   *
   * <p>Entries indexed under this category are commonly used for data that may evolve under an
   * identity or namespace. While the exact cryptographic scheme is out of scope here, consumers can
   * treat this constant as an indicator that validation and routing often involve both a key and a
   * signature or metadata bound to an identity.
   */
  SSK,

  /**
   * Public-key reference used where the store is keyed directly by public key material.
   *
   * <p>Use this for statistics and labels associated with stores whose primary lookup is the public
   * key itself (for example, registries of publisher keys or caches of verification keys). Values
   * under this category are generally read-mostly, relatively small per entry, and serve as
   * auxiliary indexes for other stores.
   */
  PUB_KEY
}

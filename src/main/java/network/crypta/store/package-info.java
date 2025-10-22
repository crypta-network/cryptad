/**
 * Storage layer for immutable blocks addressed by routing keys.
 *
 * <p>This package defines the {@link network.crypta.store.FreenetStore} SPI and concrete
 * implementations that persist or cache key–block pairs. Stores operate on a single block type per
 * instance (e.g., CHK, SSK, or pubkey) and are typically composed by the node to serve different
 * roles such as short‑term caching and long‑term persistence.
 *
 * <h2>Concepts</h2>
 *
 * <ul>
 *   <li><b>Routing key</b>: the primary lookup key used by stores (a byte array).
 *   <li><b>Full key</b>: additional key material used by higher layers to validate or construct a
 *       {@link network.crypta.store.StorableBlock}.
 *   <li><b>Block metadata</b>: optional hints passed to {@code fetch} that do not change stored
 *       content but may influence construction or selection strategies.
 * </ul>
 *
 * <h2>Concurrency</h2>
 *
 * <p>Thread-safety is implementation-defined. Many implementations are designed to be used by
 * multiple threads; consult the class documentation for guarantees and contention behavior.
 *
 * <h2>Error handling</h2>
 *
 * <ul>
 *   <li>Persistent failures (e.g., disk access) surface as {@link java.io.IOException}.
 *   <li>Attempting to insert an existing key without overwrite permission throws {@link
 *       network.crypta.store.KeyCollisionException}. This exception is lightweight by default to
 *       keep collisions inexpensive on hot paths.
 * </ul>
 *
 * <h2>Typical usage</h2>
 *
 * <pre>{@code
 * FreenetStore<StorableBlock> store = ...;
 * // Fetch by routing key; returns null when not present
 * StorableBlock block = store.fetch(routingKey, fullKey, false,
 *     /* canReadClientCache *-/ true,
 *     /* canReadSlashdotCache *-/ true,
 *     /* ignoreOldBlocks *-/ false,
 *     /* meta *-/ null);
 *
 * // Insert; may throw KeyCollisionException if overwrite=false and key exists
 * store.put(block, data, header, /* overwrite *-/ false, /* oldBlock *-/ false);
 * }</pre>
 *
 * @see network.crypta.store.FreenetStore
 * @see network.crypta.store.StorableBlock
 * @see network.crypta.store.BlockMetadata
 * @see network.crypta.store.KeyCollisionException
 * @see network.crypta.store.caching.CachingFreenetStore
 * @see network.crypta.store.saltedhash.SaltedHashFreenetStore
 */
package network.crypta.store;

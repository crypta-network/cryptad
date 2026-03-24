/**
 * Salted‑hash, on‑disk datastore for content‑addressed blocks.
 *
 * <p>This package provides a persistent hash table that maps routing keys to fixed‑size entries
 * using a per‑store salt and bounded probing. The index is intentionally lossy: collisions may
 * evict older entries once the probing window is exhausted.
 *
 * <p><b>Encryption</b>
 *
 * <ul>
 *   <li>Entry header and data are encrypted at rest using AES (Rijndael) in PCFB mode.
 *   <li>The symmetric key is the block's routing key; the IV is {@code salt || per‑entry IV}.
 *   <li>Metadata stores only a salted SHA‑256 digest of the routing key; the plain key is not
 *       written unless a build‑time debugging option is enabled.
 *   <li>See {@link network.crypta.store.saltedhash.CipherManager} for key derivation and cipher
 *       details.
 * </ul>
 *
 * <p><b>On‑disk layout</b>
 *
 * <ul>
 *   <li>{@code <name>.metadata}: 128‑byte records per slot (digested key, per‑entry IV, flags,
 *       size/generation, optional plain key).
 *   <li>{@code <name>.hd}: header+data blobs per slot; padded to a 512‑byte boundary.
 *   <li>{@code <name>.config}: store parameters and counters (including clean/dirty state).
 *   <li>{@code <name>.slotfilter}: 4‑byte per‑slot summary that marks “checked”, “occupied”, and
 *       “wrong‑store/new” states and caches the first 24 bits of the salted key to avoid
 *       unnecessary seeks. Implemented via {@link
 *       network.crypta.store.saltedhash.ResizablePersistentIntBuffer}.
 * </ul>
 *
 * <p><b>Indexing and probing</b>
 *
 * <ul>
 *   <li>Salted SHA‑256 digests of routing keys choose a primary slot and up to a small, bounded
 *       number of alternative slots. A populated slot filter makes lookups and overwrites largely
 *       O(1) in practice.
 * </ul>
 *
 * <p><b>Concurrency and lifecycle</b>
 *
 * <ul>
 *   <li>{@link network.crypta.store.saltedhash.LockManager} provides exclusive per‑offset locks. Do
 *       not hold more than one offset lock at a time to avoid deadlock.
 *   <li>A background Cleaner thread completes resizes and rebuilds the slot filter when needed.
 *   <li>The store locks its data files to enforce single‑process access.
 *   <li>Shutdown flushes configuration and the slot filter according to the active persistence
 *       policy; see {@link network.crypta.store.saltedhash.ResizablePersistentIntBuffer}.
 * </ul>
 *
 * <p><b>Limits and notes</b>
 *
 * <ul>
 *   <li>Slot filter size and related structures are limited to {@code Integer.MAX_VALUE} slots.
 *   <li>An optional “alternate store” can absorb overflow writes; reads from it remain the caller's
 *       responsibility. Do not configure two stores as each other's alternate.
 * </ul>
 *
 * <p>Main entry point: {@link network.crypta.store.saltedhash.SaltedHashFreenetStore}, which
 * implements {@link network.crypta.store.FreenetStore}.
 */
package network.crypta.store.saltedhash;

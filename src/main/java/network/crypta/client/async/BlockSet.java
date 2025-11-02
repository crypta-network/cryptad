package network.crypta.client.async;

import java.util.Set;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;

/**
 * Represents a logical set of blocks addressable by their keys.
 *
 * <p>This interface abstracts a lightweight mapping from {@link Key} or {@link ClientKey} to the
 * corresponding {@link KeyBlock} or {@link ClientKeyBlock}. Implementations may back the set with
 * an in-memory cache, a persistent index, or a remote lookup service. The abstraction is
 * intentionally small so calling code can retrieve, add, and enumerate keys without depending on
 * any particular storage layout. A typical call pattern is to {@link #add(KeyBlock)} new blocks as
 * they become available and to {@link #get(Key)} or {@link #get(ClientKey)} them later when needed.
 *
 * <p>Unless otherwise specified by an implementation, mutability and concurrency guarantees are
 * minimal: reads and writes may interleave, and {@link #keys()} may reflect a snapshot at some
 * unspecified point in time. Clients should treat returned collections as read-only views and must
 * not attempt structural modification. Implementations are encouraged, but not required, to be
 * thread-safe if they are shared across threads.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Lookup methods return {@code null} when no block is associated with the provided key.
 *   <li>The {@link #keys()} result is not guaranteed to stay updated as the set changes.
 *   <li>Blocks are identified exclusively by their keys; duplicate adds typically overwrite.
 * </ul>
 *
 * @author toad
 * @see Key
 * @see KeyBlock
 * @see ClientKey
 * @see ClientKeyBlock
 */
public interface BlockSet {

  /**
   * Returns the low-level block mapped to the given low-level key.
   *
   * <p>Performs a direct lookup using the binary {@link Key} representation typically associated
   * with internal storage. Implementations may serve the result from an in-memory cache or a
   * backing store. If no block is present for the supplied key, this method returns {@code null}
   * rather than throwing. Callers should treat the returned {@link KeyBlock} as immutable or
   * read-only from the perspective of the {@code BlockSet}; mutating it does not alter the stored
   * mapping unless explicitly defined by the implementation.
   *
   * @param key the low-level key used for addressable lookup; must not be {@code null}; values
   *     outside the accepted domain for the implementation result in no match and a {@code null}
   *     return rather than an exception.
   * @return the associated {@link KeyBlock} when present; otherwise {@code null}. The ownership of
   *     the returned object remains with the implementation; treat it as read-only and do not
   *     retain long-term if the implementation documents eviction.
   */
  KeyBlock get(Key key);

  /**
   * Adds the provided block to the set, making it available for subsequent lookups.
   *
   * <p>The block is stored under the key it carries. If a block with the same key already exists,
   * the typical behavior is to replace the previous entry; implementations may also treat the
   * operation as idempotent when the content is identical. This method does not return a value and
   * should not throw on duplicates; callers interested in prior state should query with {@link
   * #get(Key)} beforehand if needed.
   *
   * @param block the {@link KeyBlock} to add to the set; must not be {@code null}. Implementations
   *     may copy or retain a reference; callers should not modify the instance after passing it in
   *     if the implementation expects immutability.
   */
  void add(KeyBlock block);

  /**
   * Returns a view of all keys currently known to this set.
   *
   * <p>The returned {@link Set} is intended for enumeration and membership checks. It is read-only
   * from the caller’s perspective and is not guaranteed to stay synchronized with future mutations
   * of the underlying set. Some implementations may return a snapshot taken at call time, while
   * others may return a live but unmodifiable view whose contents can change between iterations. Do
   * not attempt structural modifications.
   *
   * @return a read-only set of {@link Key} values representing blocks in this set. The view is not
   *     guaranteed to remain up to date across subsequent calls or concurrent modifications and may
   *     be a snapshot or a live, unmodifiable view depending on the implementation.
   */
  Set<Key> keys();

  /**
   * Returns the high-level block mapped to the given high-level key.
   *
   * <p>This overload accepts a {@link ClientKey}, which is typically the key form used by external
   * clients or higher layers. Implementations may resolve the corresponding {@link ClientKeyBlock}
   * via an index distinct from the low-level {@link Key}/{@link KeyBlock} mapping. If no block is
   * present for the supplied key, this method returns {@code null}. As with the low-level variant,
   * callers should treat the returned block as read-only in the context of this set.
   *
   * @param key the high-level client key used for lookup; must not be {@code null}. Keys that are
   *     syntactically valid but unknown simply result in {@code null} without throwing.
   * @return the associated {@link ClientKeyBlock} when present; otherwise {@code null}. The object
   *     should be treated as immutable by callers and not held indefinitely when implementations
   *     document cache eviction or reuse.
   */
  ClientKeyBlock get(ClientKey key);
}

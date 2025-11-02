package network.crypta.client.async;

import java.util.HashMap;
import java.util.Set;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.KeyVerifyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * In‑memory {@link BlockSet} implementation that stores every block entirely in RAM.
 *
 * <p>This class provides a compact, thread-safe mapping from {@link Key} to {@link KeyBlock} and a
 * convenience lookup for {@link ClientKey} to {@link ClientKeyBlock}. It is designed for
 * lightweight use cases such as small working sets, unit tests, short‑lived tools, and scenarios
 * where the number of blocks is bounded and predictable. All data lives in a single process-local
 * {@link HashMap}, so lookups and inserts are fast but memory consumption grows with the number and
 * size of stored entries. There is no persistence, eviction policy, or size limit.
 *
 * <p>Concurrency: operations are synchronized on the instance to provide a simple safety model for
 * concurrent callers. The {@link #keys()} method returns a view backed by the internal map; callers
 * should not rely on snapshot semantics and must tolerate changes when iterating concurrently. The
 * overload {@link #get(ClientKey)} delegates to the low‑level {@link #get(Key)} and may return
 * {@code null} when the backing block is missing or fails verification.
 *
 * <ul>
 *   <li>Fast, in‑memory reads and writes; no I/O.
 *   <li>No persistence; contents are lost when the instance is discarded.
 *   <li>Duplicate adds overwrite by key; enumeration order is unspecified.
 * </ul>
 *
 * @author toad
 * @see BlockSet
 * @see Key
 * @see KeyBlock
 * @see ClientKey
 * @see ClientKeyBlock
 */
public class SimpleBlockSet implements BlockSet {
  private static final Logger LOG = LoggerFactory.getLogger(SimpleBlockSet.class);

  private final HashMap<Key, KeyBlock> blocksByKey = new HashMap<>();

  /**
   * Creates an empty in‑memory block set.
   *
   * <p>The new instance does not impose a capacity limit and performs no persistence. All methods
   * are safe to invoke from multiple threads; internal synchronization serializes basic operations.
   * Typical usage is to create a single instance, populate it via {@link #add(KeyBlock)}, and
   * perform lookups with {@link #get(Key)} or {@link #get(ClientKey)}.
   */
  public SimpleBlockSet() {
    // Intentionally empty: all state is initialized via field declarations
    // no additional setup or persistence hooks are required for this in-memory implementation.
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation stores the block using the {@link Key} embedded within {@code block}. If
   * a block with the same key already exists, it is replaced.
   *
   * @param block the block to add; must not be {@code null}. The instance may be retained
   *     internally; callers should treat it as effectively immutable after passing it in.
   */
  @Override
  public synchronized void add(KeyBlock block) {
    blocksByKey.put(block.getKey(), block);
  }

  /**
   * {@inheritDoc}
   *
   * <p>Returns {@code null} when no mapping exists. The returned {@link KeyBlock} is owned by this
   * set; callers should not modify it in ways that could violate invariants of the stored mapping.
   *
   * @param key the low‑level key to resolve; must not be {@code null}.
   * @return the associated block when present; otherwise {@code null}. The object should be treated
   *     as read‑only by callers.
   */
  @Override
  public synchronized KeyBlock get(Key key) {
    return blocksByKey.get(key);
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned view is backed by the internal map and may reflect concurrent updates. Do not
   * attempt structural modification; behavior is unspecified and may throw.
   *
   * @return a view of keys currently known to this set; contents may change over time.
   */
  @Override
  public synchronized Set<Key> keys() {
    return blocksByKey.keySet();
  }

  /**
   * {@inheritDoc}
   *
   * <p>This method converts the provided {@link ClientKey} to the corresponding node {@link Key}
   * and, when present, wraps the stored {@link KeyBlock} into a {@link ClientKeyBlock}. If the
   * backing block is missing or its contents fail verification, this method returns {@code null}.
   * The verification failure is logged at error level.
   *
   * @param key the high‑level key used for lookup; must not be {@code null}. Unknown keys result in
   *     {@code null} without throwing.
   * @return a verified {@link ClientKeyBlock} for the supplied key, or {@code null} when no mapping
   *     exists or verification fails. The returned object should be treated as immutable by
   *     callers.
   */
  @Override
  public ClientKeyBlock get(ClientKey key) {
    KeyBlock block = get(key.getNodeKey(false));
    if (block == null) return null;
    try {
      return Key.createKeyBlock(key, block);
    } catch (KeyVerifyException e) {
      LOG.error("Caught decoding block with {} : {}", key, e, e);
      return null;
    }
  }
}

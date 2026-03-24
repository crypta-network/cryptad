package network.crypta.store.saltedhash;

import java.util.Random;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.store.StorableBlock;
import network.crypta.store.StoreCallback;

/**
 * Groups the runtime dependencies required to initialize a salted-hash store.
 *
 * <p>This value object packages the store's callback, randomness source, shutdown hook, and master
 * key into a single unit for construction-time wiring. It is intended to be combined with {@link
 * SaltedHashStoreLocation} and {@link SaltedHashStoreSizing} when creating {@link
 * SaltedHashStoreParams}, keeping related runtime dependencies together and reducing call-site
 * parameter noise. The instance holds references exactly as provided and does not validate or copy
 * them.
 *
 * <p>The class does not perform any I/O or initialization. It simply stores dependencies for later
 * consumption by store factories. Because the referenced objects may be mutable or stateful,
 * callers must manage their lifetimes and thread-safety. Reference retains the master key array;
 * its contents should be treated as sensitive and must be managed by the caller.
 *
 * <ul>
 *   <li>Captures callback logic for sizing and (de-)serialization.
 *   <li>Captures the randomness source used for cryptographic decisions.
 *   <li>Captures lifecycle wiring such as shutdown hooks and master key material.
 * </ul>
 *
 * @param <T> concrete {@link StorableBlock} type produced by the callback.
 */
@SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
public final class SaltedHashStoreDependencies<T extends StorableBlock> {
  private final StoreCallback<T> callback;
  private final Random random;
  private final SemiOrderedShutdownHook shutdownHook;
  private final byte[] masterKey;

  /**
   * Creates a dependency bundle for salted-hash store construction.
   *
   * <p>This constructor records the provided references without validation, copying, or defensive
   * wrapping. It is suitable for dependency injection or configuration wiring where the same
   * callback and randomness source are reused across multiple stores. The resulting bundle is a
   * pure data carrier and does not interact with the callback, random instance, shutdown hook, or
   * master key array.
   *
   * @param callback callback used to size and (de-)serialize store entries; not validated.
   * @param random randomness source used for cryptographic decisions; stored by reference.
   * @param shutdownHook hook used to register store close tasks during initialization.
   * @param masterKey optional master key bytes used to derive per-store salts; not copied.
   */
  public SaltedHashStoreDependencies(
      StoreCallback<T> callback,
      Random random,
      SemiOrderedShutdownHook shutdownHook,
      byte[] masterKey) {
    this.callback = callback;
    this.random = random;
    this.shutdownHook = shutdownHook;
    this.masterKey = masterKey;
  }

  /**
   * Returns the callback used to size and (de-)serialize store entries.
   *
   * <p>The returned reference is the same object supplied at construction time and is not wrapped
   * or validated. Store implementations may rely on it to determine block sizes and to construct
   * {@link StorableBlock} instances. This accessor is side-effect-free and always returns the
   * stored reference.
   *
   * @return the callback reference associated with these dependencies.
   */
  public StoreCallback<T> callback() {
    return callback;
  }

  /**
   * Returns the randomness source used by the store.
   *
   * <p>The random instance is stored as provided and may be shared across stores. It is not
   * reseeded or wrapped, so callers should supply an implementation appropriate for their threat
   * model and thread-safety requirements. This method does not alter the random instance.
   *
   * @return the randomness source reference used by the store implementation.
   */
  public Random random() {
    return random;
  }

  /**
   * Returns the shutdown hook used to register store close tasks.
   *
   * <p>The hook reference is recorded without validation. Store initialization may register cleanup
   * tasks on this hook, so callers should ensure the hook remains valid for the store's lifetime.
   * This accessor does not interact with the hook and returns the stored reference directly.
   *
   * @return the shutdown hook reference associated with these dependencies.
   */
  public SemiOrderedShutdownHook shutdownHook() {
    return shutdownHook;
  }

  /**
   * Returns the master key bytes used to derive per-store salts.
   *
   * <p>The returned array is the original reference provided at construction time. It is not
   * copied, cleared, or validated, so callers must manage its confidentiality and lifecycle. Store
   * implementations may read this array during initialization; later modifications may influence
   * behavior.
   *
   * @return the master key byte array reference, possibly {@code null}.
   */
  public byte[] masterKey() {
    return masterKey;
  }
}

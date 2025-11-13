package network.crypta.client;

import network.crypta.support.api.Bucket;

/**
 * Base class for items stored in the per-key archive cache.
 *
 * <p>Provides a minimal abstraction for cached material extracted from an archive (for example, a
 * single member file or an aggregate structure). Instances are owned by an {@link
 * ArchiveStoreContext} and coordinated by {@link ArchiveManager}; the context maintains an index of
 * items per {@link ArchiveKey} and is responsible for eviction and life‑cycle transitions. This
 * class defines the small contract required by the manager: computing approximate space usage,
 * exposing data as {@link Bucket} instances, and performing low‑level cleanup when removed.
 *
 * <p>Implementations are typically lightweight handles around on‑disk or in‑memory resources. They
 * must tolerate calls while locks are held and therefore avoid blocking operations in {@link
 * #innerClose()}. Unless otherwise stated by a subtype, instances are not thread‑safe and should be
 * accessed via the owning manager’s synchronization policy.
 *
 * <ul>
 *   <li>Participates in context indexing and eviction.
 *   <li>Provides read access via {@link #getDataOrThrow()} and {@link #getReaderBucket()}.
 *   <li>Reports storage consumption with {@link #spaceUsed()}.
 * </ul>
 *
 * @see ArchiveStoreContext
 * @see ArchiveManager
 * @see ArchiveKey
 */
abstract class ArchiveStoreItem {
  /**
   * Immutable key that identifies the archive container this item belongs to.
   *
   * <p>Used for bookkeeping and eviction by the manager and its {@link ArchiveStoreContext}. The
   * reference remains constant for the lifetime of the instance.
   */
  final ArchiveKey key;

  /**
   * Owning context that indexes items sharing the same {@link ArchiveKey}.
   *
   * <p>The context coordinates insertion, removal, and bulk eviction. Calls that mutate the index
   * must follow the locking order documented on {@link ArchiveStoreContext} to avoid deadlocks.
   */
  final ArchiveStoreContext context;

  /**
   * Creates a new cached item bound to a key and context.
   *
   * @param key the immutable {@link ArchiveKey} identifying the archive this item belongs to; must
   *     not be {@code null}
   * @param context the non-{@code null} {@link ArchiveStoreContext} that owns and indexes this item
   */
  ArchiveStoreItem(ArchiveKey key, ArchiveStoreContext context) {
    this.key = key;
    this.context = context;
  }

  /**
   * Registers this item with its owning {@link ArchiveStoreContext}.
   *
   * <p>Called by implementations when the item becomes visible in the cache. The method performs a
   * constant‑time insertion into the context’s index and does not block on external resources.
   */
  protected void addToContext() {
    context.addItem(this);
  }

  /**
   * Performs low-level cleanup when the item is expelled from the cache.
   *
   * <p>Subclasses delete files or release buffers here. The method is invoked with internal locks
   * held by the manager; therefore, it must not acquire nontrivial locks or perform long‑blocking
   * operations. Implementations should limit work to quick, local actions such as file deletion.
   */
  void innerClose() {} // override in subtypes for cleanup

  /**
   * Initiates removal of this item from its context and triggers cleanup.
   *
   * <p>Delegates to {@link ArchiveStoreContext#removeItem(ArchiveStoreItem)}; subsequent calls are
   * no-ops after the first successful removal.
   */
  final void close() {
    context.removeItem(this);
  }

  /**
   * Returns the cached data as a {@link Bucket} or throws when unavailable.
   *
   * <p>Implementations create or expose a stable, readable view of the bytes currently cached for
   * this item. The returned bucket should remain usable until the caller closes or frees it, even
   * if the item is later evicted. Callers are responsible for closing the bucket to release
   * resources.
   *
   * @return a readable {@link Bucket} containing the item's cached bytes; never {@code null} when
   *     successful
   * @throws ArchiveFailureException if the data cannot be provided or a terminal error is detected
   */
  @SuppressWarnings("unused")
  abstract Bucket getDataOrThrow() throws ArchiveFailureException;

  /**
   * Reports the amount of local cache space consumed by this item.
   *
   * <p>The value is used for accounting and eviction. Implementations should return quickly and
   * avoid acquiring heavy locks since the method may be invoked while holding manager locks.
   *
   * @return size in bytes currently attributable to this item within the cache
   */
  abstract long spaceUsed();

  /**
   * Returns a {@link Bucket} that remains valid until the caller frees or finalizes it.
   *
   * <p>Unlike {@link #getDataOrThrow()}, the implementation must ensure the bucket is not freed
   * while the caller still holds a reference. This typically involves reference counting or delayed
   * reclamation. Callers must close the returned bucket when done.
   *
   * @return a durable, readable {@link Bucket} view that stays valid until explicitly freed
   * @throws ArchiveFailureException if the bucket cannot be created or contents are unavailable
   */
  abstract Bucket getReaderBucket() throws ArchiveFailureException;
}

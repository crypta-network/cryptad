package network.crypta.client.async;

import network.crypta.client.ArchiveManager;

/**
 * Bundles resources required to initialize a {@link network.crypta.client.async.ClientContext}.
 *
 * <p>This record groups the core collaborators that client-layer components need when wiring a
 * {@code ClientContext}. It acts as a simple, immutable carrier for prebuilt services, so callers
 * can pass a single value through setup paths rather than a long parameter list. Instances are
 * typically created during node startup and shared with persistence and request orchestration code,
 * which then reads the references without mutation. The record does not validate, copy, or lazily
 * create its components; it merely stores the references provided at construction time. As a
 * result, any lifecycle, ownership, or concurrency guarantees are inherited from those supplied
 * objects.
 *
 * <ul>
 *   <li>Provides a stable container for archive and healing services.
 *   <li>Allows construction-time composition without hidden side effects.
 *   <li>Delegates thread-safety to the referenced implementations.
 * </ul>
 *
 * @param archiveManager archive extraction/cache service; may be {@code null} if unavailable
 * @param healingQueue background healing queue; may be {@code null} if not configured
 * @see ArchiveManager
 * @see HealingQueue
 */
public record ClientContextResources(ArchiveManager archiveManager, HealingQueue healingQueue) {
  /**
   * Returns the archive manager reference configured for this client context.
   *
   * <p>This accessor returns exactly the instance supplied to the record constructor without
   * performing validation or defensive copying. The method is idempotent and has no side effects.
   * Callers should expect the same reference for the lifetime of this record and handle a {@code
   * null} value if the creator intentionally omitted the resource. Thread-safety and mutability are
   * determined solely by the referenced {@link ArchiveManager} implementation.
   *
   * @return the configured archive manager instance, or {@code null} when absent
   */
  public ArchiveManager getArchiveManager() {
    return archiveManager;
  }

  /**
   * Returns the healing queue reference configured for this client context.
   *
   * <p>This accessor exposes the stored queue reference as provided at construction time. It does
   * not create or wrap the queue, and it performs no synchronization or validation. The method is
   * safe to call repeatedly and will always return the same reference for this record instance.
   * Callers should be prepared for {@code null} when healing is disabled or not wired yet.
   *
   * @return the configured healing queue instance, or {@code null} when absent
   */
  public HealingQueue getHealingQueue() {
    return healingQueue;
  }
}

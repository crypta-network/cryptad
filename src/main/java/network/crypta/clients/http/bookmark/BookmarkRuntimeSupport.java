package network.crypta.clients.http.bookmark;

import java.io.File;
import network.crypta.client.async.USKCallback;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;

/**
 * Defines the runtime services that the bookmark subsystem needs from the surrounding node.
 *
 * <p>{@link BookmarkManager} uses this interface during startup, edition tracking, and deferred
 * persistence. The surface is intentionally narrow and bookmark-specific. It exposes only the
 * operations needed to locate bookmark files, manage USK subscriptions, prefetch newly discovered
 * editions, and queue delayed work. That keeps bookmark code focused on bookmark state and alert
 * handling instead of on the broader {@code NodeClientCore} API.
 *
 * <p>Implementations should preserve the legacy bookmark behavior for file locations, request
 * scheduling, and subscription wiring. The interface does not prescribe a threading model. Callers
 * should assume that callbacks and queued jobs may run asynchronously on runtime-managed threads.
 *
 * <ul>
 *   <li>Resolve the primary and backup bookmark persistence files.
 *   <li>Manage the USK subscription lifecycle for bookmark updates.
 *   <li>Trigger best-effort prefetch work for newly discovered editions.
 *   <li>Queue delayed background jobs without exposing ticker details.
 * </ul>
 *
 * @see CoreBookmarkRuntimeSupport
 */
public interface BookmarkRuntimeSupport {

  /**
   * Returns the primary bookmark persistence file.
   *
   * <p>{@link BookmarkManager} reads this file first during startup and rewrites it when the
   * current bookmark tree is flushed to disk. Implementations should return a stable node-local
   * location so restart recovery and lazy-store cycles keep using the same persistent state.
   *
   * @return the file used for normal bookmark persistence for the current node instance
   */
  File bookmarksFile();

  /**
   * Returns the backup bookmark persistence file.
   *
   * <p>The bookmark store uses this location for its safety copy and fallback load path when the
   * primary file is missing or unreadable. Implementations should keep this file paired with {@link
   * #bookmarksFile()} so backup recovery observes the same bookmark dataset and directory.
   *
   * @return the file used as the writing safety copy and recovery fallback
   */
  File backupBookmarksFile();

  /**
   * Prefetches content for a newly discovered bookmark edition.
   *
   * <p>This is a best-effort hint to the runtime, not a synchronous fetch contract. Callers use it
   * after a USK update is discovered, so the node can warm caches and begin retrieval work without
   * pulling client-construction details into bookmark domain code. The size limit is expressed in
   * bytes and should reflect the bookmark's configured prefetch budget.
   *
   * @param uri the discovered edition URI whose target content should be prefetched
   * @param maxSize the maximum number of bytes the prefetch should attempt to retrieve
   */
  void prefetchUpdatedEdition(FreenetURI uri, long maxSize);

  /**
   * Subscribes to updates for a bookmark USK.
   *
   * <p>Callers typically subscribe when a bookmark is loaded or added, then later pair that
   * subscription with {@link #unsubscribeFromUsk(USK, USKCallback)} when the bookmark is removed or
   * the manager shuts down. The runtime implementation owns request-client details and any
   * underlying subscription bookkeeping that the bookmark package should not see directly.
   *
   * @param usk the updatable key to monitor for newer bookmark editions
   * @param callback the callback that receives edition notifications from the runtime
   */
  void subscribeToUsk(USK usk, USKCallback callback);

  /**
   * Removes a USK subscription previously created through this runtime support.
   *
   * <p>Callers should pass the same USK and callback pair that was previously given to {@link
   * #subscribeToUsk(USK, USKCallback)}. Implementations are responsible for translating that pair
   * into the underlying runtime's unsubscribing behavior and for releasing any associated resources
   * or tracking state owned by the runtime.
   *
   * @param usk the updatable key that should no longer be monitored for updates
   * @param callback the callback instance that should be detached from update delivery
   */
  void unsubscribeFromUsk(USK usk, USKCallback callback);

  /**
   * Queues a delayed bookmark persistence job.
   *
   * <p>Bookmark code uses this hook to coalesce repeated mutations behind a timer instead of
   * writing on every state change. The delay is expressed in milliseconds from the time of
   * scheduling. This interface does not define whether equal jobs are merged, deduplicated, or run
   * on a specific executor; those policy details belong to the implementation.
   *
   * @param job the work item that should run after the requested delay expires
   * @param delayMillis the scheduling delay, in milliseconds, before the job may run
   */
  void queueLazyStore(Runnable job, long delayMillis);
}

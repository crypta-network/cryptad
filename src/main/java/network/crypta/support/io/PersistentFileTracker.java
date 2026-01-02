package network.crypta.support.io;

import java.io.File;

/**
 * Coordinates persistent temporary files and deferred resource freeing across restarts and commit
 * boundaries.
 *
 * <p>This contract is used by the persistence subsystem to:
 *
 * <ul>
 *   <li>Claim pre-existing temporary files discovered during startup so they are not removed by the
 *       post-startup cleanup.
 *   <li>Expose a monotonic commit barrier identifier via {@link #commitID()} that callers record at
 *       creation time and later present back to {@link #delayedFree(DelayedFree, long)} when a
 *       resource is being freed.
 *   <li>Schedule actual deletion of resources implementing {@link DelayedFree} only after the
 *       transaction recording their deletion has been durably persisted, to avoid data loss on
 *       unclean shutdowns.
 *   <li>Provide access to the persistent temporary directory and its {@link FilenameGenerator}.
 * </ul>
 *
 * <p>This interface also extends {@link DiskSpaceChecker}; implementations should use the same
 * directory context when evaluating free-space policies.
 *
 * <p><strong>Threading:</strong> Callers may invoke methods from multiple threads. Implementations
 * should be thread-safe and avoid long blocking operations on hot paths.
 *
 * <p><strong>Exceptions:</strong> None of the methods declare checked exceptions. Implementations
 * should prefer returning normally (or logging) for expected conditions and only throw for fatal
 * errors unrelated to low disk space or routine cleanup.
 */
public interface PersistentFileTracker extends DiskSpaceChecker {

  /**
   * Claims an existing temporary file during startup so it is not deleted by the one-time cleanup
   * that follows initialization.
   *
   * <p>Typical usage: while restoring state at node startup, components that reconstruct buckets or
   * buffers call this method to mark files they own. After initialization completes, the
   * implementation removes any unclaimed files that match its naming scheme. Files created after
   * startup do not need to be registered.
   *
   * @param file file under the persistent temporary directory to retain; must be non-{@code null}
   */
  void register(File file);

  /**
   * Returns the current commit barrier identifier.
   *
   * <p>The value is strictly positive and monotonically increases when the implementation advances
   * to a new persistence window (for example, after handing off a batch of deletions to be freed
   * post-commit). Callers capture this value when creating a resource and pass it back to {@link
   * #delayedFree(DelayedFree, long)} when releasing that resource so the tracker can decide whether
   * freeing is safe immediately or must be deferred until after the next successful commit.
   *
   * @return a positive, monotonically increasing identifier
   */
  long commitID();

  /**
   * Requests that a resource be freed, deferring the actual release until it is safe to do so.
   *
   * <p>If {@code createdCommitID} equals the current {@link #commitID()}, implementations may call
   * {@link DelayedFree#realFree()} immediately because no commit barrier is required. Otherwise,
   * they queue the resource and perform the release only after the next successful persistence
   * commit. Implementations also typically treat {@code createdCommitID == 0} as “created before
   * the last restart”, which requires deferral until after a commit. Restored wrappers use {@code
   * 0} to signal this pre-restart state.
   *
   * <p>Concurrency: callers may invoke this from I/O threads. Implementations should synchronize
   * their internal state as needed.
   *
   * @param bucket resource to free after the appropriate commit barrier
   * @param createdCommitID the {@link #commitID()} value captured when the resource was created; 0
   *     indicates creation before the last restart in typical implementations
   */
  void delayedFree(DelayedFree bucket, long createdCommitID);

  /**
   * Returns the directory used to store persistent temporary files.
   *
   * @return the canonical temporary directory managed by this tracker
   */
  File dir();

  /**
   * Returns the filename generator bound to the persistent temporary directory.
   *
   * @return the generator used for naming and migration of temp files
   */
  FilenameGenerator getGenerator();
}

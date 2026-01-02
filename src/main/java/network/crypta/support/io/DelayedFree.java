package network.crypta.support.io;

/**
 * Contract for resources that participate in deferred freeing after a successful persistence
 * commit.
 *
 * <p>Implementations typically wrap storage primitives (for example, a {@code Bucket} or a
 * random-access buffer) so that their {@code free()} is not executed immediately but is scheduled
 * by a {@link PersistentFileTracker}. The tracker records the deletion in the persistent state and
 * then calls {@link #realFree()} only after the corresponding transaction has been durably written
 * (e.g., after the client layer state file has been updated). This reduces the risk of losing
 * bookkeeping in the event of an unclean shutdown between mutation and checkpointing.
 *
 * <p>Implementations are expected to be used only by the persistence subsystem; typical callers
 * should use the normal {@code free()}/close methods on the wrapped types and let the tracker
 * coordinate the actual release.
 */
public interface DelayedFree {

  /**
   * Indicates whether the resource has been marked for deferred freeing.
   *
   * <p>Trackers use this signal to confirm that {@link #realFree()} should actually release the
   * underlying storage when processing a batch that was scheduled earlier.
   *
   * @return {@code true} if a prior call requested freeing (for example, via a wrapper's {@code
   *     free()}), otherwise {@code false}
   */
  boolean toFree();

  /**
   * Performs the immediate release of the underlying resource.
   *
   * <p>This method is invoked by {@link PersistentFileTracker} after the transaction recording the
   * deletion has been successfully written to disk, or immediately when no commit barrier is
   * required. It must not rely on external state that is only present before the commit.
   *
   * <p>Threading: callers may invoke this from a background thread owned by the persistence layer.
   * Implementations should avoid long blocking operations.
   *
   * <p>Idempotency: callers invoke this once per lifecycle; repeated calls are not expected.
   */
  void realFree();
}

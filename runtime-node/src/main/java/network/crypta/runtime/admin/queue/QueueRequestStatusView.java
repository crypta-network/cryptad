package network.crypta.runtime.admin.queue;

/**
 * Describes the minimal runtime-owned view of a queued request status.
 *
 * <p>This interface exists so runtime-admin can reason about queue entries without importing
 * protocol-specific status classes. Implementations expose only the fields that the current
 * diagnostics and cleanup flows need: a stable identifier, coarse success state, persistence mode,
 * and whether the request's total block count is finalized.
 *
 * <p>Callers should treat instances as read-only views for a specific queue traversal. The
 * interface intentionally omits richer progress, failure, and protocol metadata because those
 * details still belong to the backend-specific queue layer.
 */
public interface QueueRequestStatusView {
  /**
   * Returns the stable queue identifier.
   *
   * <p>The identifier is the value runtime-admin can pass back into mutation methods such as
   * removal, restart, or reprioritization. It is expected to remain stable for the lifetime of the
   * corresponding queued request.
   *
   * @return backend-specific identifier used to refer to this queued request later
   */
  String getIdentifier();

  /**
   * Returns whether the request completed successfully.
   *
   * <p>A value of {@code false} does not distinguish between an in-progress request and a completed
   * request that failed. Callers use this only as a coarse success signal when building summary
   * counts or deciding whether a cleanup action should proceed.
   *
   * @return {@code true} when the backend reports the request as successful
   */
  boolean hasSucceeded();

  /**
   * Returns whether the request is persistent.
   *
   * <p>This flag tells runtime-admin whether the request belongs to a persistent queue mode rather
   * than an ephemeral one. Cleanup logic combines it with other status flags before removing
   * finished downloads.
   *
   * @return {@code true} when the request uses a persistent queue mode
   */
  boolean isPersistent();

  /**
   * Returns whether the total block count is finalized.
   *
   * <p>This reports whether the backend considers the request's total block count settled enough
   * for callers to rely on it. Runtime-admin uses the flag as part of its legacy cleanup criteria
   * for finished downloads.
   *
   * @return {@code true} when the request's total block count is finalized
   */
  boolean isTotalFinalized();
}

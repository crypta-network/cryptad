package network.crypta.runtime.spi;

/**
 * Queue-control capability for persistent-request operations exposed through the runtime SPI.
 *
 * <p>This port gives infrastructure code a narrow way to interact with the daemon's
 * persistent-request queue without traversing daemon-only types such as client contexts,
 * persistence runners, or ticker implementations. Typical callers are protocol handlers that need
 * to look up, mutate, remove, or list persistent requests while preserving the daemon's existing
 * queueing and retry behavior.
 *
 * <p>The surface is intentionally small. Callers can observe whether persistent storage has already
 * been killed, submit one unit of persistent work with an explicit priority, and schedule a plain
 * delayed retry. The API is JDK-only and does not expose ownership, batching, cancellation, or
 * scheduler internals. Treat this port as a live runtime view for request-queue control, not as a
 * general-purpose scheduling abstraction.
 *
 * <ul>
 *   <li>Keep protocol mapping and error handling in the caller.
 *   <li>Use {@link RequestQueuePriority} to preserve legacy queue ordering.
 *   <li>Prefer {@link #scheduleLater(Runnable, long)} only for lightweight delayed retries.
 * </ul>
 */
public interface RequestQueuePort {
  /**
   * Returns whether the underlying persistence database has already been killed.
   *
   * <p>Callers use this as a conservative guard for protocol paths that historically stopped
   * enqueueing work once persistence became irreversibly unavailable. A {@code true} result means
   * the storage layer is already gone rather than merely busy, so callers typically preserve the
   * legacy behavior of skipping further queue interaction entirely.
   *
   * @return {@code true} when persistence storage has been killed and new work should not be
   *     attempted; otherwise {@code false}
   */
  boolean isPersistenceDatabaseKilled();

  /**
   * Submits one persistent-request job using the requested queue priority.
   *
   * <p>The task runs on the daemon's persistent job infrastructure using the requested queue
   * priority. Implementations may reject the submission when persistence is disabled, storage is
   * already gone, or shutdown has progressed far enough that new work is no longer accepted. In
   * those cases callers should preserve their existing protocol behavior instead of retrying
   * blindly.
   *
   * @param task persistent-request unit of work to execute on the runtime-owned queue
   * @param priority requested scheduling priority that preserves the legacy queue semantics
   * @throws RequestQueueUnavailableException if the runtime cannot accept new persistent-request
   *     work because persistence is unavailable
   */
  void submitPersistentJob(RequestQueueTask task, RequestQueuePriority priority)
      throws RequestQueueUnavailableException;

  /**
   * Schedules a plain delayed task using the runtime's lightweight timer facility.
   *
   * <p>This is intended for short resubmission delays or backpressure retries. The task is not
   * persisted, is run at or after the requested delay according to the daemon's existing ticker
   * semantics, and should therefore remain lightweight and safe to requeue if the caller repeats
   * the operation.
   *
   * @param task delayed task to schedule on the runtime-owned timer facility
   * @param delayMillis delay in milliseconds before the task should be invoked
   */
  void scheduleLater(Runnable task, long delayMillis);
}

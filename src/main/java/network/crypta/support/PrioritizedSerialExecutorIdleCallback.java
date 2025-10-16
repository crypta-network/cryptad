package network.crypta.support;

/**
 * Callback that is notified when a {@link PrioritizedSerialExecutor} has remained idle for a
 * configured period with no runnable tasks.
 *
 * <p>Invocation semantics:
 *
 * <ul>
 *   <li>Called on the executor's worker thread for single-threaded execution.
 *   <li>Invoked at most once per "idle episode" immediately before the worker thread would exit due
 *       to idleness. If the implementation enqueues new work, processing continues and the worker
 *       does not exit.
 *   <li>Called outside the executor's internal queue lock; implementations may safely submit new
 *       tasks to the same executor.
 * </ul>
 *
 * <p>Timing: The idle duration is determined by the executor's configuration (defaults to several
 * minutes in the current implementation). Exact timing is not guaranteed and may be subject to
 * thread scheduling.
 *
 * <p>Threading and performance: Implementations must be thread-safe and should return promptly.
 * Long-running or blocking work here can delay shutdown or the processing of subsequently queued
 * tasks. Any exception thrown by the implementation is caught and logged by the executor.
 */
public interface PrioritizedSerialExecutorIdleCallback {

  /**
   * Notifies that the associated executor has been idle for approximately its configured idle
   * timeout.
   *
   * <p>This method is invoked on the executor's worker thread and outside internal synchronization.
   * Implementations may enqueue new tasks (including back onto the same {@link
   * PrioritizedSerialExecutor}). If no task is enqueued, the worker thread may terminate shortly
   * after this callback returns.
   *
   * <p>Implementations should complete quickly and avoid blocking I/O or long computations.
   *
   * @throws RuntimeException if the implementation throws; the executor catches and logs any
   *     runtime exceptions and continues according to its idle handling policy.
   */
  void onIdle();
}

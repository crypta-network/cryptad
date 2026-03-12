package network.crypta.support;

import org.jetbrains.annotations.NotNull;

/**
 * Executor interface with optional priority awareness and lightweight thread-state introspection.
 *
 * <p>This extends {@link java.util.concurrent.Executor} and adds methods to query how many worker
 * threads are currently waiting or running at each priority level. Implementations are expected to
 * interpret task priority from the submitted {@link Runnable} when possible (for example, when the
 * task implements a project-specific priority carrier such as {@code
 * network.crypta.node.PrioRunnable}) and otherwise fall back to a default priority.
 *
 * <p>Unlike the standard {@link java.util.concurrent.Executor}, none of the {@code execute(...)}
 * methods in this abstraction are required to throw {@link
 * java.util.concurrent.RejectedExecutionException}. Implementations should strive to accept tasks
 * and either execute them promptly or queue them. If rejection is possible, the conditions should
 * be documented by the implementation.
 *
 * <p>Thread-safety: Implementations should be thread-safe; all methods may be called concurrently
 * from multiple threads. The introspection methods return snapshots that can become stale
 * immediately after return and are intended for diagnostics and coarse-grained scheduling only.
 *
 * <p>Indexing of priority arrays: The shape and indexing of arrays returned by the introspection
 * methods are implementation-defined, but generally align with the priority values used by the
 * implementation (e.g., indices may correspond to {@code
 * network.crypta.support.io.NativeThread.PriorityLevel} values). Values must be non-negative.
 * Unknown or unused indices should contain {@code 0}.
 */
public interface PriorityAwareExecutor extends java.util.concurrent.Executor {

  /**
   * Submits a task for execution.
   *
   * <p>The task may execute asynchronously on a worker thread or, in some implementations, inline
   * on the caller thread. Priority, if any, is typically inferred from the {@code job} instance
   * (e.g., when it implements a priority-bearing interface) or defaults to an implementation
   * standard.
   *
   * <p>This method does not require throwing {@link
   * java.util.concurrent.RejectedExecutionException}; implementations should document any rejection
   * behavior they choose to expose.
   *
   * @param job the task to run; must be non-{@code null}
   * @throws RuntimeException implementations may throw unchecked exceptions at submission time
   *     (e.g., due to shut down or illegal state)
   * @implNote Implementations should reject {@code null} jobs, typically by throwing {@link
   *     NullPointerException}.
   */
  @Override
  void execute(@NotNull Runnable job);

  /**
   * Submits a task with a human-readable label for logging and diagnostics.
   *
   * <p>Implementations may incorporate {@code jobName} into worker thread names and log output to
   * aid debugging. Priority is inferred as described for {@link #execute(Runnable)}.
   *
   * @param job the task to run; must be non-{@code null}
   * @param jobName descriptive label for the task; may be {@code null} or empty
   * @throws RuntimeException implementations may throw unchecked exceptions at submission time
   * @implNote Implementations should accept {@code null} or empty {@code jobName} values and may
   *     sanitize or truncate them for display or thread naming.
   */
  void execute(Runnable job, String jobName);

  /**
   * Submits a task with a label and an origin hint used by some schedulers.
   *
   * <p>The {@code fromTicker} flag is a hint indicating that the call originates from a
   * scheduler/ticker context. Some implementations (e.g., those that may delegate thread creation
   * back to a ticker at higher priority) consult this hint to avoid recursion or priority-inversion
   * loops. Callers outside the scheduling infrastructure should prefer {@link #execute(Runnable,
   * String)}.
   *
   * @param job the task to run; must be non-{@code null}
   * @param jobName descriptive label for the task; may be {@code null} or empty
   * @param fromTicker {@code true} if invoked from a ticker/scheduler thread; otherwise {@code
   *     false}. This is a best-effort hint and does not change task semantics beyond
   *     implementation-specific scheduling behaviors.
   * @throws RuntimeException implementations may throw unchecked exceptions at submission time
   * @implNote Implementations may treat {@code fromTicker} as a hint only and ignore it.
   */
  void execute(Runnable job, String jobName, boolean fromTicker);

  /**
   * Returns the number of worker threads currently waiting for work at each priority level.
   *
   * <p>The returned array is a snapshot and may become out of date immediately. Its length and
   * indexing scheme are implementation-defined but should be consistent with the executor's notion
   * of priority levels. All elements are greater than or equal to zero.
   *
   * @return a new array containing counts of waiting threads per priority
   */
  int[] waitingThreads();

  /**
   * Returns the number of worker threads currently executing tasks at each priority level.
   *
   * <p>The returned array is a snapshot and may become out of date immediately. Its length and
   * indexing scheme are implementation-defined but should be consistent with the executor's notion
   * of priority levels. All elements are greater than or equal to zero.
   *
   * @return a new array containing counts of running threads per priority
   */
  int[] runningThreads();

  /**
   * Returns the total number of worker threads that are currently waiting for work.
   *
   * <p>This is a fast-path aggregate useful for coarse-grained load monitoring. It typically equals
   * the sum of {@link #waitingThreads()} but may be computed more efficiently by implementations.
   * Values are non-negative.
   *
   * @return the total count of waiting threads across all priorities
   */
  int getWaitingThreadsCount();
}

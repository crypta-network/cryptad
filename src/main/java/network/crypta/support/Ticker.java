package network.crypta.support;

/**
 * Schedules execution of {@link Runnable} tasks for a future time.
 *
 * <p>This interface abstracts a lightweight timer/scheduler used across the node to run work after
 * a delay or at a given wall-clock time. Implementations typically coordinate with a high-priority
 * "ticker" thread and a {@link PriorityAwareExecutor} to balance latency and throughput. It is a
 * best-effort facility: tasks run at or after their scheduled time; no strict real-time guarantees
 * are implied.
 *
 * <p>Thread-safety: Implementations are expected to be thread-safe. All methods may be called from
 * multiple threads concurrently.
 *
 * <p>Scheduling semantics and priorities:
 *
 * <ul>
 *   <li>{@code runOnTickerAnyway} forces initial dispatch from the ticker thread even when direct
 *       submission to the underlying executor would be possible. This is useful when callers rely
 *       on the ticker's higher thread priority or need deterministic hand-off points in tests.
 *   <li>{@code noDupes} suppresses queuing duplicate tasks that are already pending. Duplication is
 *       typically determined by object identity of the {@link Runnable}; callers must still ensure
 *       their tasks are idempotent and properly synchronized because this option does not prevent
 *       concurrent execution if a previously queued instance has already started.
 * </ul>
 *
 * <p>Time base: Unless stated otherwise by the implementation, delays are in milliseconds and
 * absolute times are interpreted as milliseconds since the epoch as returned by {@link
 * System#currentTimeMillis()}.
 *
 * <p>Cancellation: {@link #removeQueuedJob(Runnable)} removes a pending task on a best-effort
 * basis. It does not interrupt a task that is already running.
 *
 * @see PriorityAwareExecutor
 */
public interface Ticker {

  /**
   * Queues a task to run after the given delay.
   *
   * <p>The task runs no earlier than {@code now + offset}. Actual execution may occur later due to
   * load, thread scheduling, or implementation limits.
   *
   * @param job the task to execute; must be non-{@code null}
   * @param offset delay in milliseconds before run; negative values are treated as an immediate run
   *     in many schedulers
   * @throws NullPointerException if {@code job} is {@code null} (implementation-dependent)
   */
  void queueTimedJob(Runnable job, long offset);

  /**
   * Queues a task to run after the given delay with an optional name and scheduling hints.
   *
   * <p>When {@code runOnTickerAnyway} is {@code true}, the scheduler begins execution from the
   * ticker thread (which usually runs at a higher OS/VM priority) before handing off to a worker if
   * needed. When {@code noDupes} is {@code true}, a task equal to an already queued instance is not
   * queued again, but this does not guarantee that multiple instances will not be running
   * concurrently if earlier instances have already started.
   *
   * @param job the task to execute; must be non-{@code null}
   * @param name optional thread/task name used for diagnostics; may be {@code null} or empty
   * @param offset delay in milliseconds before run
   * @param runOnTickerAnyway if {@code true}, start from the ticker thread even when direct
   *     executor submission is possible; useful for priority elevation and certain tests
   * @param noDupes if {@code true}, ignore the task when an equivalent pending instance already
   *     exists; implies {@code runOnTickerAnyway}
   * @throws NullPointerException if {@code job} is {@code null} (implementation-dependent)
   */
  void queueTimedJob(
      Runnable job, String name, long offset, boolean runOnTickerAnyway, boolean noDupes);

  /**
   * Returns the underlying {@link PriorityAwareExecutor} used for task execution.
   *
   * <p>The returned executor may be used for direct submissions in advanced scenarios, but callers
   * should prefer the timed methods of this interface for delayed or absolute-time scheduling.
   *
   * @return the executor associated with this ticker
   */
  PriorityAwareExecutor getExecutor();

  /**
   * Attempts to remove a previously queued task that has not yet started.
   *
   * <p>This is a best-effort cancellation of pending work. If the task is already running or has
   * already executed, this method has no effect. Implementations may choose identity-based matching
   * (the same {@link Runnable} instance) when locating the queued task.
   *
   * @param job the task instance to remove; must be non-{@code null}
   * @throws NullPointerException if {@code job} is {@code null} (implementation-dependent)
   */
  void removeQueuedJob(Runnable job);

  /**
   * Queues a task to run at a specific absolute time.
   *
   * <p>The task runs at or after {@code time}. The {@code time} value is interpreted as an absolute
   * wall-clock timestamp in milliseconds (typically {@link System#currentTimeMillis()}). Actual
   * execution may occur later due to load or scheduling. The {@code runOnTickerAnyway} and {@code
   * noDupes} semantics mirror those in {@link #queueTimedJob(Runnable, String, long, boolean,
   * boolean)}.
   *
   * @param runner the task to execute; must be non-{@code null}
   * @param name optional thread/task name used for diagnostics; may be {@code null} or empty
   * @param time absolute time in milliseconds at which to run
   * @param runOnTickerAnyway if {@code true}, start from the ticker thread even when direct
   *     executor submission is possible
   * @param noDupes if {@code true}, ignore the task when an equivalent pending instance already
   *     exists; implies {@code runOnTickerAnyway}
   * @throws NullPointerException if {@code runner} is {@code null} (implementation-dependent)
   */
  void queueTimedJobAbsolute(
      Runnable runner, String name, long time, boolean runOnTickerAnyway, boolean noDupes);
}

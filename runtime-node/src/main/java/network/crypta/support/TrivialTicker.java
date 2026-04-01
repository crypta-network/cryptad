package network.crypta.support;

import java.util.HashMap;
import java.util.Objects;
import java.util.Timer;
import java.util.TimerTask;
import network.crypta.node.FastRunnable;

/**
 * A simple {@link Ticker} implementation backed by a single daemon {@link java.util.Timer}.
 *
 * <p>It schedules {@link Runnable} tasks to run after a delay or at an absolute time. Tasks that
 * implement {@link FastRunnable} run inline on the timer's thread; all others are handed off to the
 * provided {@link PriorityAwareExecutor}. Duplicate suppression is performed by keeping a mapping
 * from task instance to its {@link TimerTask} when {@code noDupes} is requested.
 *
 * <p>Thread-safety: All public methods are thread-safe and may be called concurrently. Internally,
 * the class synchronizes on the {@code TrivialTicker} instance to coordinate state and on-time
 * removal of pending tasks. Note that {@link Timer} uses a single worker thread: any long-running
 * inline task (i.e., a {@code FastRunnable}) delays subsequent timer events.
 *
 * <p>Time base: delays and absolute times are expressed in milliseconds and interpreted against
 * {@link System#currentTimeMillis()}.
 *
 * <p>Hints: The {@code runOnTickerAnyway} hint from {@link Ticker} is currently ignored by this
 * implementation.
 *
 * <p>Usage note: If deploying this to replace code that depends on distinct thread priorities,
 * ensure the underlying executor is configured appropriately. Creating the executor with a higher
 * priority at startup is a common approach.
 *
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 */
public class TrivialTicker implements Ticker {

  private final Timer timer = new Timer(true);

  private final PriorityAwareExecutor executor;

  private final HashMap<Runnable, TimerTask> jobs = new HashMap<>();

  private boolean running = true;

  /**
   * Creates a ticker that schedules work and, for non-{@link FastRunnable} tasks, executes them on
   * the given {@link PriorityAwareExecutor}.
   *
   * @param executor the executor used for scheduled tasks that do not implement {@link
   *     FastRunnable}; must be non-null
   */
  public TrivialTicker(PriorityAwareExecutor executor) {
    this.executor = executor;
  }

  /**
   * Queues a task to run after the given delay.
   *
   * <p>If {@code job} implements {@link FastRunnable}, it runs inline on the timer thread;
   * otherwise it is submitted to the {@link PriorityAwareExecutor} with a diagnostic name of the
   * form {@code "Delayed task: " + job}.
   *
   * @param job the task to execute; must be non-{@code null}
   * @param offset delay in milliseconds before run
   * @throws NullPointerException if {@code job} is {@code null}
   * @throws IllegalArgumentException if {@code offset} is negative (thrown by {@link Timer})
   */
  @Override
  public void queueTimedJob(final Runnable job, long offset) {
    Objects.requireNonNull(job, "job");
    TimerTask t =
        new TimerTask() {
          @Override
          public void run() {
            // Remove before running in case the task re-schedules itself.
            synchronized (TrivialTicker.this) {
              jobs.remove(job);
            }

            if (job instanceof FastRunnable) {
              job.run();
            } else {
              executor.execute(job, "Delayed task: " + job);
            }
          }
        };

    synchronized (this) {
      if (!running) return;

      timer.schedule(t, offset);
      jobs.put(job, t);
    }
  }

  /**
   * Queues a task to run after the given delay with an optional name and scheduling hints.
   *
   * <p>If {@code noDupes} is {@code true} and an equivalent task instance is already pending (by
   * identity of the {@link Runnable} object), the request is ignored. If {@code job} implements
   * {@link FastRunnable}, it runs inline; otherwise the task is submitted to the executor under the
   * provided {@code name}. The {@code runOnTickerAnyway} hint is currently ignored.
   *
   * @param job the task to execute; must be non-{@code null}
   * @param name a diagnostic name for executor submissions; may be {@code null} or empty
   * @param offset delay in milliseconds before run
   * @param runOnTickerAnyway hint that is ignored in this implementation
   * @param noDupes if {@code true}, suppress queuing when the same task instance is already pending
   * @throws NullPointerException if {@code job} is {@code null}
   * @throws IllegalArgumentException if {@code offset} is negative (thrown by {@link Timer})
   */
  @Override
  public void queueTimedJob(
      final Runnable job,
      final String name,
      long offset,
      boolean runOnTickerAnyway,
      boolean noDupes) {
    Objects.requireNonNull(job, "job");
    TimerTask t =
        new TimerTask() {

          @Override
          public void run() {
            // Remove before running in case the task re-schedules itself.
            synchronized (TrivialTicker.this) {
              jobs.remove(job);
            }

            if (job instanceof FastRunnable) {
              job.run();
            } else {
              executor.execute(job, name);
            }
          }
        };

    synchronized (this) {
      if (!running) return;

      if (noDupes && jobs.containsKey(job)) return;

      timer.schedule(t, offset);
      jobs.put(job, t);
    }
  }

  /**
   * Attempts to remove a previously queued task that has not yet started.
   *
   * <p>This is a best-effort cancellation. If the task is already running or was never queued, this
   * method does nothing.
   *
   * @param job the task instance to remove; must be non-{@code null}
   * @throws NullPointerException if {@code job} is {@code null}
   */
  @Override
  public void removeQueuedJob(final Runnable job) {
    if (job == null) {
      throw new NullPointerException("job");
    }
    synchronized (this) {
      if (!running) return;

      TimerTask t = jobs.remove(job);
      if (t != null) {
        t.cancel();
      }
    }
  }

  /**
   * Reschedules a task to run after a new delay.
   *
   * <p>If the task is already queued, it is removed and queued again with the new offset. If it is
   * not yet queued, it is queued. The operation executes atomically with respect to this ticker's
   * internal synchronization and does not perform duplicate checks.
   *
   * @param job the task to reschedule; must be non-{@code null}
   * @param name a diagnostic name for executor submissions; may be {@code null} or empty
   * @param newOffset delay in milliseconds before run
   * @throws NullPointerException if {@code job} is {@code null}
   * @throws IllegalArgumentException if {@code newOffset} is negative (thrown by {@link Timer})
   */
  public void rescheduleTimedJob(final Runnable job, final String name, long newOffset) {
    synchronized (this) {
      removeQueuedJob(job);
      queueTimedJob(job, name, newOffset, false, false); // No duplicate check; already synchronized
    }
  }

  private Thread shutdownThread = null;

  /**
   * Requests an orderly shutdown and blocks until the timer's worker thread terminates.
   *
   * <p>Postcondition: After this method returns, the underlying {@link Timer} is canceled and no
   * further tasks will be executed. Subsequent scheduling or removal calls are best-effort no-ops
   * because {@link #running} is set to {@code false}.
   *
   * <p>Interrupt handling: This method guarantees completion of the shutdown even if the calling
   * thread is interrupted while waiting. Any {@link InterruptedException} encountered while waiting
   * is remembered and the thread's interrupt status is re-asserted before returning.
   */
  @SuppressWarnings("java:S2142") // Intentionally defer re-interruption until method exit to avoid
  // immediate rethrow/spin from wait()/join(); the contract requires completing shutdown first.
  public void shutdown() {
    synchronized (this) {
      running = false;

      timer.schedule(
          new TimerTask() {

            @Override
            public void run() {
              // Cancel from the timer thread so this task becomes the final execution.
              timer.cancel();
              synchronized (TrivialTicker.this) {
                shutdownThread = Thread.currentThread();
                TrivialTicker.this.notifyAll();
              }
            }
          },
          0);
      boolean interrupted = false;

      while (shutdownThread == null) {
        try {
          wait();
        } catch (InterruptedException _) {
          // Preserve interrupt request; continue honoring the shutdown contract.
          interrupted = true;
        }
      }

      while (shutdownThread.isAlive()) {
        try {
          shutdownThread.join();
        } catch (InterruptedException _) {
          // Preserve interrupt request; continue waiting for the worker to terminate.
          interrupted = true;
        }
      }

      if (interrupted) {
        Thread.currentThread().interrupt();
      }
    }
  }

  /** Returns the executor used for non-{@link FastRunnable} tasks. */
  @Override
  public PriorityAwareExecutor getExecutor() {
    return executor;
  }

  /**
   * Queues a task to run at the specified absolute time.
   *
   * <p>If {@code time} is in the past, the task is scheduled to run as soon as possible (zero
   * delay). The {@code runOnTickerAnyway} hint is currently ignored. Duplicate suppression is
   * applied when {@code noDupes} is {@code true} as described for {@link #queueTimedJob(Runnable,
   * String, long, boolean, boolean)}.
   *
   * @param runner the task to execute; must be non-{@code null}
   * @param name a diagnostic name for executor submissions; may be {@code null} or empty
   * @param time absolute time in milliseconds since the epoch at which to run
   * @param runOnTickerAnyway hint that is ignored in this implementation
   * @param noDupes if {@code true}, suppress queuing when the same task instance is already pending
   * @throws NullPointerException if {@code runner} is {@code null}
   */
  @Override
  public void queueTimedJobAbsolute(
      Runnable runner, String name, long time, boolean runOnTickerAnyway, boolean noDupes) {
    long now = System.currentTimeMillis();
    long offset = time - now;
    if (offset < 0) offset = 0;
    queueTimedJob(runner, name, offset, runOnTickerAnyway, noDupes);
  }
}

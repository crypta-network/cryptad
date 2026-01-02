package network.crypta.support;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import network.crypta.node.NodeStats;
import network.crypta.node.PrioRunnable;
import network.crypta.support.io.NativeThread;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Single-threaded executor with internal priority queues.
 *
 * <p>This executor runs submitted {@link Runnable} tasks on a single worker thread ("runner") and
 * preserves FIFO ordering within the same priority. It supports multiple internal priority levels;
 * the next task is selected either from lowest index to highest (when {@code invertOrder == false})
 * or from highest to lowest (when {@code invertOrder == true}).
 *
 * <p>Thread-safety: All public methods are thread-safe. Tasks are executed serially by the runner.
 * The implementation uses a single intrinsic lock around the priority queues for coordination.
 *
 * <p>Lifecycle: {@link #start(PriorityAwareExecutor, String)} wires the underlying executor used to
 * launch the runner thread. If there is already queued work at the time of {@code start}, a runner
 * is spawned immediately; otherwise the executor remains idle until the first task is enqueued.
 * Subsequent calls to {@code execute(...)} will lazily start the runner as needed.
 *
 * <p>Statistics: When {@link NodeStats} is provided, the implementation emits an immediate
 * monitoring hook right before running a job. The current behavior reports a duration of {@code 0L}
 * at that point; consumers should treat it as a start marker rather than an elapsed duration.
 *
 * @since 2
 */
public class PrioritizedSerialExecutor implements PriorityAwareExecutor {
  private static final Logger LOG = LoggerFactory.getLogger(PrioritizedSerialExecutor.class);

  // No static initialization required

  private final List<ArrayDeque<Runnable>> jobs;
  private final int priority;
  private final int defaultPriority;
  private boolean waiting;
  private final boolean invertOrder;

  private String name;
  private PriorityAwareExecutor realExecutor;
  private boolean running;
  private final PrioritizedSerialExecutorIdleCallback callback;

  private static final long DEFAULT_JOB_TIMEOUT = MINUTES.toMillis(5);
  private final long jobTimeout;

  private final Runner runner = new Runner();

  private final NodeStats statistics;

  class Runner implements PrioRunnable {

    Thread current;

    /** Returns the logical runner priority used in {@link #runningThreads()}. */
    @Override
    public int getPriority() {
      return priority;
    }

    /**
     * Runs tasks from the internal queues until the executor becomes idle or is asked to exit.
     *
     * <p>Concurrency notes:
     *
     * <ul>
     *   <li>Spurious wakeups are handled; the runner rechecks the queues after every wait.
     *   <li>If interrupted while idle, the runner resets internal state under the queue lock and
     *       returns; when work is present a new runner is started to avoid losing tasks.
     *   <li>Failures thrown by tasks are caught to keep the single-threaded executor alive.
     * </ul>
     */
    @Override
    public void run() {
      if (!acquireRunnerThread()) return;
      try {
        boolean calledIdleCallback = false;
        while (true) {
          Runnable job = waitForNextJob();
          if (job == null) {
            // Only honor interrupts if the wait actually aborted (no job dequeued).
            if (Thread.interrupted()) {
              boolean restart;
              synchronized (jobs) {
                restart = hasQueuedJobs() && realExecutor != null;
                running = false;
                current = null;
              }
              if (restart) reallyStart();
              return;
            }
            if (tryExit(calledIdleCallback)) {
              return;
            }
            calledIdleCallback = invokeIdleCallback();
            continue;
          }
          calledIdleCallback = false;
          executeJob(job);
        }
      } finally {
        synchronized (jobs) {
          current = null;
          running = false;
        }
      }
    }

    /**
     * Sets {@link #current} to the calling thread if a previous runner is not alive.
     *
     * @return {@code true} if the caller successfully became the runner; {@code false} if a running
     *     thread already owns the role.
     */
    private boolean acquireRunnerThread() {
      synchronized (jobs) {
        if (current != null && current.isAlive()) {
          LOG.warn("Already running a thread for {} !!", this);
          return false;
        }
        current = Thread.currentThread();
        return true;
      }
    }

    /**
     * Waits for and returns the next queued job, or {@code null} if no job became available before
     * the timeout.
     *
     * <p>Synchronization: Must be called by the runner. This method acquires the queue lock and
     * releases it only when returning.
     *
     * @return the next runnable to execute, or {@code null} on timeout or interrupt; checked
     *     exceptions are handled internally
     */
    private Runnable waitForNextJob() {
      synchronized (jobs) {
        Runnable job = checkQueue();
        if (job != null) return job;
        waiting = true;
        try {
          long deadline = System.currentTimeMillis() + jobTimeout;
          long remaining = jobTimeout;
          Runnable polled;
          while ((polled = checkQueue()) == null && remaining > 0) {
            jobs.wait(remaining);
            remaining = deadline - System.currentTimeMillis();
          }
          return polled;
        } catch (InterruptedException _) {
          // Restore interrupt status and let caller decide (we won't remove from the queue here
          // to avoid dropping work on exit).
          Thread.currentThread().interrupt();
          return null;
        } finally {
          waiting = false;
        }
      }
    }

    /**
     * Attempts to transition the executor to the non-running state when idle.
     *
     * <p>Resets the {@code running/current} flags under the queue lock only if there is still no
     * work and either there is no idle callback or it was already called for this idle episode.
     *
     * @param calledIdleCallback whether {@link #invokeIdleCallback()} has already been invoked in
     *     this idle episode
     * @return {@code true} when the state was reset and the runner should return
     */
    private boolean tryExit(boolean calledIdleCallback) {
      synchronized (jobs) {
        // Exit only if there is still no work and there's no callback to run (or it was run).
        if (!hasQueuedJobs() && (calledIdleCallback || callback == null)) {
          // Reset state under the same lock to avoid a race where enqueuers see running=true and
          // skip restarting the runner.
          running = false;
          current = null;
          return true;
        }
        return false;
      }
    }

    /**
     * Invokes the optional idle callback, logging and swallowing failures to keep the runner alive.
     *
     * @return always {@code true}; the return value is used as a sticky flag by the caller
     */
    private boolean invokeIdleCallback() {
      try {
        if (callback != null) callback.onIdle();
      } catch (Exception e) {
        LOG.error("Idle callback failed.", e);
      }
      return true;
    }

    /**
     * Executes a single job with error isolation.
     *
     * <p>Exceptions: Catches {@link Throwable} to prevent the worker thread from dying on {@link
     * Error}. This mirrors the resilience behavior used in other components.
     *
     * <p>Statistics: Emits an immediate monitoring hook before running the job. The duration value
     * is {@code 0L} by design to make the signal observable by tests/observers that verify right
     * after the job starts.
     *
     * @param job the runnable to execute; never {@code null}
     */
    @SuppressWarnings("java:S1181") // Catch Throwable to avoid the thread dying.
    private void executeJob(Runnable job) {
      try {
        if (LOG.isDebugEnabled()) LOG.debug("Running job {}", job);
        long start = System.currentTimeMillis();
        // Emit an immediate hook so consumers reliably observe the event even if they verify right
        // after the runnable starts. Duration is reported as 0.
        if (statistics != null) {
          statistics.reportDatabaseJob(job.toString(), 0L);
        }
        job.run();
        long end = System.currentTimeMillis();
        if (LOG.isDebugEnabled()) {
          LOG.debug("Job {} took {}ms", job, end - start);
        }
      } catch (Throwable e) {
        LOG.error("Job failed: {}", job, e);
      }
    }

    /** Removes and returns the next runnable according to the configured priority order. */
    private Runnable checkQueue() {
      return invertOrder
          ? pollFromIndexRange(jobs.size() - 1, -1, -1)
          : pollFromIndexRange(0, jobs.size(), 1);
    }

    /**
     * Scans priorities in the given range and removes the first runnable encountered.
     *
     * @param start first index to check (inclusive)
     * @param endExclusive end index (exclusive)
     * @param step increment (+1 forward, -1 backward)
     * @return the dequeued runnable, or {@code null} when none exists
     */
    private Runnable pollFromIndexRange(int start, int endExclusive, int step) {
      for (int i = start; i != endExclusive; i += step) {
        if (!jobs.get(i).isEmpty()) {
          if (LOG.isDebugEnabled()) LOG.debug("Chosen job at priority {}", i);
          return jobs.get(i).removeFirst();
        }
      }
      return null;
    }

    /** Returns {@code true} when at least one priority queue is non-empty. */
    private boolean hasQueuedJobs() {
      for (ArrayDeque<Runnable> job : jobs) {
        if (!job.isEmpty()) return true;
      }
      return false;
    }
  }

  /**
   * Creates a prioritized serial executor.
   *
   * <p>The executor maintains {@code internalPriorityCount} internal FIFO queues. Tasks that
   * implement {@link PrioRunnable} contribute their own priority; other tasks use {@code
   * defaultPriority}. Selection order depends on {@code invertOrder}.
   *
   * @param priority logical priority used to report the running thread via {@link
   *     #runningThreads()}
   * @param internalPriorityCount number of internal priority queues; must be {@code > 0}
   * @param defaultPriority priority to use for tasks that are not {@link PrioRunnable}
   * @param invertOrder when {@code true}, higher indices are preferred first; when {@code false},
   *     lower indices are preferred first
   * @param jobTimeout maximum time in milliseconds the runner waits while idle before attempting to
   *     exit
   * @param callback optional hook invoked once per idle episode before the runner attempts to exit;
   *     may be {@code null}
   * @param statistics optional statistics sink; when non-null an immediate monitoring hook is
   *     emitted before each job starts
   */
  public PrioritizedSerialExecutor(
      int priority,
      int internalPriorityCount,
      int defaultPriority,
      boolean invertOrder,
      long jobTimeout,
      PrioritizedSerialExecutorIdleCallback callback,
      NodeStats statistics) {
    this.jobs = new ArrayList<>(internalPriorityCount);
    for (int i = 0; i < internalPriorityCount; i++) {
      this.jobs.add(new ArrayDeque<>());
    }
    this.priority = priority;
    this.defaultPriority = defaultPriority;
    this.invertOrder = invertOrder;
    this.jobTimeout = jobTimeout;
    this.callback = callback;
    this.statistics = statistics;
  }

  /**
   * Creates a prioritized serial executor using default settings.
   *
   * <p>Uses a {@code 5m} idle timeout, no idle callback, and no statistics reporting.
   *
   * @param priority logical priority used to report the running thread
   * @param internalPriorityCount number of internal priority queues
   * @param defaultPriority priority for tasks that are not {@link PrioRunnable}
   * @param invertOrder when {@code true}, higher indices are preferred first
   */
  public PrioritizedSerialExecutor(
      int priority, int internalPriorityCount, int defaultPriority, boolean invertOrder) {
    this(
        priority,
        internalPriorityCount,
        defaultPriority,
        invertOrder,
        DEFAULT_JOB_TIMEOUT,
        null,
        null);
  }

  /**
   * Wires the underlying executor and assigns a display name for the runner thread.
   *
   * <p>If work is already queued, a runner is started immediately. Otherwise, the executor will
   * start on the first subsequent submission.
   *
   * @param realExecutor underlying executor used to start the runner; must be non-{@code null}
   * @param name descriptive name for the runner thread; may be {@code null}
   */
  public void start(PriorityAwareExecutor realExecutor, String name) {
    this.realExecutor = realExecutor;
    this.name = name;
    synchronized (jobs) {
      boolean empty = true;
      for (ArrayDeque<Runnable> l : jobs) {
        if (!l.isEmpty()) {
          empty = false;
          break;
        }
      }
      if (!empty) reallyStart();
    }
  }

  // Starts the runner while holding the queue lock; assumes {@code !running}.
  private void reallyStart() {
    synchronized (jobs) {
      if (running) {
        LOG.warn("Not reallyStart()ing: ALREADY RUNNING");
        return;
      }
      running = true;
      if (LOG.isDebugEnabled()) LOG.debug("Starting thread... {} : {}", name, runner);
      realExecutor.execute(runner, name);
    }
  }

  /**
   * Submits a task with a default label.
   *
   * @param job the runnable to execute
   */
  @Override
  public void execute(@NotNull Runnable job) {
    execute(job, "<noname>");
  }

  /**
   * Submits a task with a label; priority is inferred from {@link PrioRunnable} if present.
   *
   * @param job the runnable to execute
   * @param jobName a descriptive label used in logs
   */
  @Override
  public void execute(Runnable job, String jobName) {
    int prio = defaultPriority;
    if (job instanceof PrioRunnable runnable) prio = runnable.getPriority();
    execute(job, prio, jobName);
  }

  /**
   * Submits a task with an explicit internal priority and label.
   *
   * @param job the runnable to execute
   * @param prio internal priority index (0..N-1)
   * @param jobName a descriptive label used in logs
   */
  public void execute(Runnable job, int prio, String jobName) {
    synchronized (jobs) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Queueing {} : {} priority {}, executor state: running={} waiting={}",
            jobName,
            job,
            prio,
            running,
            waiting);
      jobs.get(prio).addLast(job);
      jobs.notifyAll();
      if (!running && realExecutor != null) {
        reallyStart();
      }
    }
  }

  /**
   * Submits a task if an identical instance is not already queued at the given priority.
   *
   * @param job the runnable to enqueue if absent
   * @param prio internal priority index (0..N-1)
   * @param jobName a descriptive label used in logs
   */
  public void executeNoDupes(Runnable job, int prio, String jobName) {
    synchronized (jobs) {
      if (jobs.get(prio).contains(job)) {
        if (LOG.isDebugEnabled()) LOG.debug("Not queueing job: Job already queued: {}", job);
        return;
      }

      if (LOG.isDebugEnabled())
        LOG.debug(
            "Queueing {} : {} priority {}, executor state: running={} waiting={}",
            jobName,
            job,
            prio,
            running,
            waiting);

      jobs.get(prio).addLast(job);
      jobs.notifyAll();
      if (!running && realExecutor != null) {
        reallyStart();
      }
    }
  }

  /**
   * Submits a task with a label. The {@code fromTicker} hint is ignored in this implementation.
   *
   * @param job the runnable to execute
   * @param jobName a descriptive label used in logs
   * @param fromTicker unused; retained for interface compatibility
   */
  @Override
  public void execute(Runnable job, String jobName, boolean fromTicker) {
    execute(job, jobName);
  }

  /**
   * Returns a snapshot of running runner threads per logical priority.
   *
   * @return an array of length {@code NativeThread.JAVA_PRIORITY_RANGE + 1} with either {@code 0}
   *     or {@code 1} at {@code priority}
   */
  @Override
  public int[] runningThreads() {
    int[] retval = new int[NativeThread.JAVA_PRIORITY_RANGE + 1];
    if (running) retval[priority] = 1;
    return retval;
  }

  /**
   * Returns a snapshot of waiting runner threads per logical priority.
   *
   * @return an array of length {@code NativeThread.JAVA_PRIORITY_RANGE + 1} with either {@code 0}
   *     or {@code 1} at {@code priority}
   */
  @Override
  public int[] waitingThreads() {
    int[] retval = new int[NativeThread.JAVA_PRIORITY_RANGE + 1];
    synchronized (jobs) {
      if (waiting) retval[priority] = 1;
    }
    return retval;
  }

  /**
   * Returns whether the current thread is the executor's runner.
   *
   * @return {@code true} when invoked from the runner thread
   */
  public boolean onThread() {
    Thread currentThread = Thread.currentThread();
    synchronized (jobs) {
      return runner.current == currentThread;
    }
  }

  /**
   * Returns a snapshot of queued jobs grouped by priority.
   *
   * <p>The returned array is a copy. Each sub-array contains the current FIFO order for that
   * priority at the time of the snapshot.
   *
   * @return a snapshot of the queues
   */
  public Runnable[][] getQueuedJobsByPriority() {
    final Runnable[][] ret = new Runnable[jobs.size()][];

    synchronized (jobs) {
      for (int i = 0; i < jobs.size(); ++i) {
        ret[i] = jobs.get(i).toArray(new Runnable[0]);
      }
    }

    return ret;
  }

  /**
   * Returns the number of queued jobs for a given internal priority.
   *
   * @param priority internal priority index (0..N-1)
   * @return the number of enqueued jobs at {@code priority}
   */
  public int getQueueSize(int priority) {
    synchronized (jobs) {
      return jobs.get(priority).size();
    }
  }

  /**
   * Returns the total number of runner threads currently waiting for work.
   *
   * @return either {@code 0} or {@code 1} for this implementation
   */
  @Override
  public int getWaitingThreadsCount() {
    synchronized (jobs) {
      return (waiting ? 1 : 0);
    }
  }
}

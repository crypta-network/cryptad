package network.crypta.support;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.TreeMap;
import network.crypta.node.FastRunnable;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * High‑priority, time‑based scheduler that dispatches tasks from a dedicated ticker thread.
 *
 * <p>This implementation accepts delayed and absolute‑time tasks and drains them in timestamp
 * order. Tasks that implement {@link FastRunnable} execute inline on the ticker thread to minimize
 * latency; other tasks are handed off to a {@link PriorityAwareExecutor}. Callers can optionally
 * suppress enqueuing duplicates and can request that immediate tasks still start on the ticker
 * thread for priority or testing reasons.
 *
 * <p>Thread‑safety: All public methods are thread‑safe. Internal structures are protected by a lock
 * on {@code timedJobsByTime}. The ticker sleeps by calling {@link #sleep(long)}, which uses a timed
 * {@code wait} on {@code this}; wake‑ups use {@link #wakeUp()}.
 *
 * <p>Time base and units: Delays and times are in milliseconds. Absolute times have been
 * interpreted as milliseconds since the epoch as returned by {@link System#currentTimeMillis()}.
 *
 * <p>Fairness and guarantees: Execution is the best‑effort. Tasks run at or after their scheduled
 * time; no real‑time guarantees are made. When {@code noDupes} is enabled, duplicate tasks already
 * queued for the same or an earlier time are not added again.
 *
 * @see Ticker
 * @see PriorityAwareExecutor
 */
public class PrioritizedTicker implements Ticker, Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(PrioritizedTicker.class);

  // Prefix used in error logs; legacy label retained for log search compatibility.
  private static final String ERR_PREFIX = "Caught in PacketSender: ";

  private record Job(String name, Runnable task) {

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof Job)) {
        return false;
      }
      // Ignore the name; we are only interested in the job, needed for noDupes.
      return ((Job) o).task == task;
    }

    @Override
    public int hashCode() {
      return task.hashCode();
    }
  }

  // Map of run time (ms since epoch) -> Job or Job[] scheduled for that instant.
  private final TreeMap<Long, Object> timedJobsByTime;

  private final HashMap<Job, Long> timedJobsQueued;
  final NativeThread myThread;
  final PriorityAwareExecutor executor;
  static final int MAX_SLEEP_TIME = 200;

  /**
   * Creates a ticker backed by the given executor and a dedicated high‑priority thread.
   *
   * <p>The thread is named {@code "Ticker thread for <portNumber>"} and marked as a daemon. It is
   * created at {@link network.crypta.support.io.NativeThread.PriorityLevel#MAX_PRIORITY}.
   *
   * @param executor the {@link PriorityAwareExecutor} used to run non‑fast tasks; must be
   *     non‑{@code null}
   * @param portNumber used for thread naming and diagnostics
   */
  public PrioritizedTicker(PriorityAwareExecutor executor, int portNumber) {
    this.executor = executor;
    timedJobsByTime = new TreeMap<>();
    timedJobsQueued = new HashMap<>();
    myThread =
        new NativeThread(
            this,
            "Ticker thread for " + portNumber,
            NativeThread.PriorityLevel.MAX_PRIORITY.value,
            false);
    myThread.setDaemon(true);
  }

  /**
   * Starts the ticker thread.
   *
   * <p>Subsequent invocations after the thread has been started may throw {@link
   * IllegalThreadStateException} as per {@link Thread#start()}.
   *
   * @throws IllegalThreadStateException if the thread has already been started
   */
  public void start() {
    LOG.info("Starting Ticker");
    myThread.start();
  }

  /**
   * Runs the ticker loop on its dedicated thread.
   *
   * <p>The loop drains due tasks, dispatches them, and sleeps for a bounded interval (no greater
   * than {@link #MAX_SLEEP_TIME}) or until {@link #wakeUp()} is called. The method restores the
   * interrupt flag and exits when interrupted. Non‑fatal {@link Throwable}s from task execution are
   * logged and do not terminate the ticker; fatal {@link VirtualMachineError}s are propagated.
   */
  @Override
  @SuppressWarnings({"java:S2139", "java:S1181"})
  public void run() {
    if (LOG.isDebugEnabled()) LOG.debug("In Ticker.run()");
    while (!Thread.currentThread().isInterrupted()) {
      try {
        realRun();
      } catch (InterruptedException _) {
        // Restore interrupt status and exit loop so caller controls lifecycle via interrupt.
        Thread.currentThread().interrupt();
        break;
      } catch (VirtualMachineError fatal) {
        // Don't try to keep running on truly fatal JVM conditions.
        LOG.error(ERR_PREFIX + "{}", fatal, fatal);
        throw fatal;
      } catch (Throwable t) {
        // Keep the ticker alive even on Errors (e.g., AssertionError, LinkageError).
        LOG.error(ERR_PREFIX + "{}", t, t);
      }
    }
  }

  private void realRun() throws InterruptedException {
    long now = System.currentTimeMillis();
    List<Job> jobsToRun = new ArrayList<>();
    long sleepTime = drainDueJobs(now, jobsToRun);
    if (!jobsToRun.isEmpty()) {
      executeJobs(jobsToRun);
    }
    if (sleepTime > 0) {
      sleep(sleepTime);
    }
  }

  private long drainDueJobs(long now, List<Job> jobsToRun) {
    long sleepTime = MAX_SLEEP_TIME;
    synchronized (timedJobsByTime) {
      while (!timedJobsByTime.isEmpty()) {
        Long tRun = timedJobsByTime.firstKey();
        if (tRun <= now) {
          Object o = timedJobsByTime.remove(tRun);
          if (o instanceof Job[] jobs) {
            for (Job r : jobs) {
              jobsToRun.add(r);
              timedJobsQueued.remove(r);
            }
          } else {
            Job r = (Job) o;
            jobsToRun.add(r);
            timedJobsQueued.remove(r);
          }
        } else {
          sleepTime = Math.min(sleepTime, tRun - now);
          break;
        }
      }
    }
    return sleepTime;
  }

  private void executeJobs(List<Job> jobsToRun) {
    for (Job r : jobsToRun) {
      if (LOG.isDebugEnabled()) LOG.debug("Running {}", r);
      runJob(r);
    }
  }

  private void runJob(Job r) {
    if (r.task instanceof FastRunnable) {
      runFast(r);
    } else {
      runViaExecutor(r);
    }
  }

  /**
   * Runs a {@link FastRunnable} inline on the ticker thread.
   *
   * <p>We catch non-fatal {@link Throwable}s so that a failure in one fast job does not abort the
   * current batch and cause subsequently drained jobs to be dropped. Fatal VM errors are rethrown
   * to allow the outer loop to handle them.
   */
  @SuppressWarnings("java:S1181")
  private void runFast(Job r) {
    try {
      r.task.run();
    } catch (VirtualMachineError fatal) {
      throw fatal;
    } catch (Throwable t) {
      LOG.error("Caught {} running {}", t, r, t);
    }
  }

  /**
   * Runs a job via the executor. On failures, retries after a short delay.
   *
   * <p>We treat any non-fatal {@link Throwable} from the executor as retryable and re-queue the job
   * for later. Fatal VM errors ({@link VirtualMachineError}) are rethrown to allow the outer loop
   * to abort as designed.
   */
  @SuppressWarnings("java:S1181")
  private void runViaExecutor(Job r) {
    try {
      executor.execute(r.task, r.name, true);
    } catch (VirtualMachineError fatal) {
      throw fatal;
    } catch (Throwable t) {
      LOG.error(ERR_PREFIX + "{}", t, t);
      LOG.warn("Will retry above failed operation...");
      queueTimedJob(r.task, r.name, 200, true, false);
    }
  }

  /**
   * Sleeps up to {@code sleepTime} milliseconds or until {@link #wakeUp()} notifies this monitor.
   *
   * <p>Design notes: - This uses a single timed {@code wait(sleepTime)} (no {@code while} loop) on
   * purpose to maximize wake-up responsiveness. When notified, we return promptly, so the ticker
   * can re-check the timed-job queue outside the monitor and run any newly scheduled work without
   * waiting out the remainder of the original sleep window. - Spurious wakeup is acceptable for
   * this method: an early return only causes an early re-drain of the queue, which is safe and
   * desirable for latency. The queue/predicate is not tied to this monitor; it lives in {@code
   * timedJobsByTime} and is checked immediately after this method returns.
   *
   * <p>Suppression rationale: Sonar rule S2274 recommends guarding {@code wait} in a loop to
   * re-check a predicate after spurious wakeups. Here, the predicate lives outside the monitor and
   * is intentionally re-checked by the caller after returning. Wrapping the wait in a loop to
   * "sleep until the original deadline" would reintroduce latency and defeat the purpose of {@link
   * #wakeUp()}.
   */
  @SuppressWarnings("java:S2274")
  protected void sleep(long sleepTime) throws InterruptedException {
    if (LOG.isDebugEnabled()) LOG.debug("Sleeping for {}", sleepTime);
    synchronized (this) {
      // Return early when notified to preserve wake-up responsiveness.
      wait(sleepTime);
    }
  }

  /**
   * Queues a task to run after the given delay.
   *
   * <p>If {@code offset <= 0}, the task may run immediately by submitting directly to the executor,
   * unless a caller requires ticker‑thread dispatch via the more detailed overload.
   *
   * @param job the task to run; must be non‑{@code null}
   * @param offset delay in milliseconds before execution; negative values are treated as zero
   */
  @Override
  public void queueTimedJob(Runnable job, long offset) {
    queueTimedJob(job, "Scheduled job: " + job, offset, false, false);
  }

  /**
   * Queues a task to run after the given delay with a name and scheduling hints.
   *
   * <p>When {@code offset <= 0} and {@code runOnTickerAnyway == false}, the task is submitted
   * directly to the executor and may execute on a worker thread. When {@code runOnTickerAnyway ==
   * true}, the task is scheduled on the ticker regardless of the offset, which can help preserve
   * ticker‑thread priority or provide deterministic hand‑off points in tests.
   *
   * <p>When {@code noDupes == true}, an equivalent task already pending is not queued again. This
   * check is relatively expensive (O(n) in the number of queued tasks at the same timestamp) but
   * prevents unbounded growth for periodic reschedulers.
   *
   * @param runner the task to execute; may implement {@link FastRunnable} to run inline on the
   *     ticker thread
   * @param name diagnostic label used by the executor and logs; may be {@code null}
   * @param offset delay in milliseconds from {@link System#currentTimeMillis()}
   * @param runOnTickerAnyway if {@code true}, start from the ticker thread even when an immediate
   *     executor submission is possible
   * @param noDupes if {@code true}, suppress re‑queuing when an equivalent pending task exists;
   *     implies {@code runOnTickerAnyway}
   */
  @Override
  public void queueTimedJob(
      Runnable runner, String name, long offset, boolean runOnTickerAnyway, boolean noDupes) {
    // Run directly *if* that won't cause any priority problems.
    long now = System.currentTimeMillis();
    if (offset < 0) offset = 0;
    queueTimedJobInner(runner, name, now + offset, offset, runOnTickerAnyway, noDupes);
  }

  /**
   * Queues a task to run at a specific absolute wall‑clock time.
   *
   * <p>If {@code time} has already passed, the task is scheduled to run as soon as possible.
   *
   * @param runner the task to execute; may implement {@link FastRunnable}
   * @param name diagnostic label used by the executor and logs; may be {@code null}
   * @param time absolute time in milliseconds since the epoch (see {@link
   *     System#currentTimeMillis()}) at which to run
   * @param runOnTickerAnyway if {@code true}, start from the ticker thread even when immediate
   *     executor submission is possible
   * @param noDupes if {@code true}, suppress re‑queuing when an equivalent pending task exists
   */
  @Override
  public void queueTimedJobAbsolute(
      Runnable runner, String name, long time, boolean runOnTickerAnyway, boolean noDupes) {
    long now = System.currentTimeMillis();
    queueTimedJobInner(runner, name, time, time - now, runOnTickerAnyway, noDupes);
  }

  /**
   * Queue a job at a specific absolute time.
   *
   * @param runJobAt The absolute time at which the job should run.
   * @param offset The offset in milliseconds from "now" (i.e., some recent call to
   *     System.currentTimeMillis()).
   */
  private void queueTimedJobInner(
      Runnable runner,
      String name,
      long runJobAt,
      long offset,
      boolean runOnTickerAnyway,
      boolean noDupes) {
    if (noDupes) runOnTickerAnyway = true;
    if (offset <= 0 && !runOnTickerAnyway) {
      if (LOG.isDebugEnabled()) LOG.debug("Running directly: {}", runner);
      executor.execute(runner, name);
      return;
    }
    Job job = new Job(name, runner);
    synchronized (timedJobsByTime) {
      if (shouldSkipRequeue(job, runJobAt, noDupes, name, runner)) return;
      Object o = timedJobsByTime.get(runJobAt);
      switch (o) {
        case null -> timedJobsByTime.put(runJobAt, job);
        case Job job1 -> timedJobsByTime.put(runJobAt, new Job[] {job1, job});
        case Job[] r -> {
          Job[] jobs = Arrays.copyOf(r, r.length + 1);
          jobs[jobs.length - 1] = job;
          timedJobsByTime.put(runJobAt, jobs);
        }
        default -> {
          // Should never happen.
        }
      }
      timedJobsQueued.put(job, runJobAt);
    }
    if (offset < MAX_SLEEP_TIME) {
      wakeUp();
    }
  }

  private boolean shouldSkipRequeue(
      Job job, long runJobAt, boolean noDupes, String name, Runnable runner) {
    if (!noDupes) return false;
    Long alreadyQueuedAt = timedJobsQueued.get(job);
    if (alreadyQueuedAt == null) return false;
    if (alreadyQueuedAt <= runJobAt) {
      LOG.info("Not re-running as already queued: {} for {}", runner, name);
      return true;
    }
    // Delete the existing job because the new job will run first.
    removeQueuedJobInner(job, alreadyQueuedAt);
    return false;
  }

  /** Wake up the ticker so it can re‑check and dispatch queued jobs sooner. */
  void wakeUp() {
    // Wake up if needed
    synchronized (this) {
      notifyAll();
    }
  }

  /**
   * Returns the executor used by this ticker for non‑fast tasks.
   *
   * @return the associated {@link PriorityAwareExecutor}
   */
  @Override
  public PriorityAwareExecutor getExecutor() {
    return executor;
  }

  int queuedJobs() {
    synchronized (timedJobsByTime) {
      return timedJobsQueued.size();
    }
  }

  int queuedJobsUniqueTimes() {
    synchronized (timedJobsByTime) {
      return timedJobsByTime.size();
    }
  }

  /**
   * Attempts to remove a previously queued task that has not yet started.
   *
   * <p>This is the best‑effort cancellation. If the task is not queued or has already started, this
   * method does nothing.
   *
   * @param runnable the task instance to remove; must be the same {@link Runnable} instance that
   *     was queued
   */
  @Override
  public void removeQueuedJob(Runnable runnable) {
    Job job = new Job(null, runnable);
    synchronized (timedJobsByTime) {
      Long t = timedJobsQueued.remove(job);
      if (t != null) {
        removeQueuedJobInner(job, t);
      }
    }
  }

  /**
   * Remove a queued job from the internal structures other than timedJobsQueued. The caller must
   * check that it is present in timedJobsQueued, remove from that structure, and call this method,
   * all inside the timedJobsByTime lock.
   *
   * @param job The job to remove.
   * @param t The time at which it is scheduled.
   */
  private void removeQueuedJobInner(Job job, Long t) {
    Object o = timedJobsByTime.get(t);
    assert (o != null);
    if (o instanceof Job) {
      assert (o.equals(job));
      timedJobsByTime.remove(t);
      return;
    }
    handleArrayRemoval((Job[]) o, job, t);
  }

  private void handleArrayRemoval(Job[] jobs, Job job, Long t) {
    if (jobs.length == 1) {
      assert (jobs[0].equals(job));
      timedJobsByTime.remove(t);
      return;
    }
    Job[] newJobs = new Job[jobs.length - 1];
    int x = 0;
    for (Job oldjob : jobs) {
      if (oldjob.equals(job)) {
        continue;
      }
      newJobs[x++] = oldjob;
      assert (x != jobs.length); // Must be in jobs array.
    }
    assert (x != 0); // Not duplicated.
    if (x == 1) {
      timedJobsByTime.put(t, newJobs[0]);
    } else {
      if (x != newJobs.length) newJobs = Arrays.copyOf(newJobs, x);
      timedJobsByTime.put(t, newJobs);
      assert (x == jobs.length - 1);
    }
  }
}

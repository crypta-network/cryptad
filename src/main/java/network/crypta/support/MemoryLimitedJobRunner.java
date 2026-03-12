package network.crypta.support;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import network.crypta.node.PrioRunnable;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Schedules {@link MemoryLimitedJob} instances subject to a shared capacity budget.
 *
 * <p>This runner starts jobs while sufficient capacity of a limited resource (typically memory) is
 * available, otherwise it queues them for later execution. Similar utilities exist in general
 * executors, but this type provides lightweight accounting and backpressure based on a
 * caller-supplied capacity metric.
 *
 * <h3>Thread-safety</h3>
 *
 * <ul>
 *   <li>All public methods are {@code synchronized} on this instance. Callbacks into jobs execute
 *       on threads provided by the {@link PriorityAwareExecutor} and must not call back into this
 *       class in a way that could deadlock.
 *   <li>Internal counters and queues are only accessed while holding this monitor.
 * </ul>
 *
 * <h3>Units and accounting</h3>
 *
 * <ul>
 *   <li>{@code capacity} and all sizes passed to this runner use the same unit (usually bytes).
 *   <li>Each started job receives a {@link MemoryLimitedChunk} initialized with its declared {@code
 *       initialAllocation}. Jobs can only decrease (release) usage via the chunk API.
 *   <li>The runner admits queued jobs when both capacity and the {@code maxThreads} limit permit.
 * </ul>
 *
 * <h3>Ordering</h3>
 *
 * Jobs are bucketed into FIFO queues per priority. Lower numeric priority values represent higher
 * scheduling preference. When capacity is available the runner scans priority queues from the
 * lowest index to highest and starts the first admissible job.
 *
 * @author toad
 */
public class MemoryLimitedJobRunner {
  private static final Logger LOG = LoggerFactory.getLogger(MemoryLimitedJobRunner.class);

  /**
   * Native thread priority used for worker tasks executed through the {@link
   * PriorityAwareExecutor}. The numeric value maps to {@link
   * NativeThread.PriorityLevel#LOW_PRIORITY}.
   */
  public static final int THREAD_PRIORITY = NativeThread.PriorityLevel.LOW_PRIORITY.value;

  private long capacity;

  /**
   * Current accounted usage of the limited resource.
   *
   * <p>Units match {@link #capacity}. Guarded by this instance's monitor.
   */
  private long counter;

  /** Queued jobs that cannot start yet, bucketed by priority (FIFO within each bucket). */
  private final List<Deque<MemoryLimitedJob>> jobs;

  private final PriorityAwareExecutor executor;
  private int runningThreads; // Number of jobs currently running (each on a worker thread).
  private int maxThreads; // Upper bound on concurrently running jobs regardless of capacity.
  private boolean
      shutdown; // When set, new jobs are not accepted and waiters are notified on drain.

  // No static initialization required.

  /**
   * Creates a new runner with the given capacity and concurrency limit.
   *
   * @param capacity total budget available for running jobs; units are caller-defined but must be
   *     consistent (typically bytes)
   * @param maxThreads maximum number of jobs permitted to run concurrently
   * @param executor executor used to run jobs; must not be {@code null}
   * @param priorities number of distinct priority buckets used by {@link
   *     #queueJob(MemoryLimitedJob)}
   * @since 1
   */
  public MemoryLimitedJobRunner(
      long capacity, int maxThreads, PriorityAwareExecutor executor, int priorities) {
    this.capacity = capacity;
    this.counter = 0;
    this.jobs = new ArrayList<>(priorities);
    for (int i = 0; i < priorities; i++) jobs.add(new ArrayDeque<>());
    this.executor = executor;
    this.maxThreads = maxThreads;
  }

  /**
   * Queues a job or starts it immediately if capacity and concurrency permit.
   *
   * <p>If this runner is shutting down, the method ignores the job and returns. If the job's {@code
   * initialAllocation} exceeds the configured capacity, an exception is thrown.
   *
   * @param job the job to run; must not be {@code null}
   * @throws IllegalArgumentException if the job's initial allocation is larger than {@link
   *     #getCapacity()}
   */
  public synchronized void queueJob(final MemoryLimitedJob job) {
    if (shutdown) return;
    if (job.initialAllocation > capacity)
      throw new IllegalArgumentException(
          "Job size " + job.initialAllocation + " > capacity " + capacity);
    if (LOG.isDebugEnabled()) LOG.debug("Queueing job {} at priority {}", job, job.getPriority());
    jobs.get(job.getPriority()).add(job);
    maybeStartJobs();
  }

  /*
   * Updates usage accounting and, optionally, marks the worker as finished.
   *
   * Called by {@link MemoryLimitedChunk} when a job releases some or all of its allocation. A
   * zero-size release with {@code finishedThread=true} is valid and decrements the running thread
   * count (e.g., for jobs whose initial allocation is zero).
   */
  synchronized void deallocate(long size, boolean finishedThread) {
    if (size < 0) throw new IllegalArgumentException();
    if (size > 0) {
      assert (size <= counter);
      counter -= size;
    }
    if (finishedThread) {
      runningThreads--;
      if (shutdown) notifyAll();
    }
    maybeStartJobs();
  }

  // Scans priority queues and starts the first admissible job while limits allow.
  private synchronized void maybeStartJobs() {
    if (shutdown) return;
    while (true) {
      MemoryLimitedJob job = null;
      int prio = 0;
      for (; prio < jobs.size(); prio++) {
        job = jobs.get(prio).peekFirst();
        if (job != null) break;
      }
      if (job == null) return;
      if (job.initialAllocation + counter <= capacity && runningThreads < maxThreads) {
        jobs.get(prio).removeFirst();
        startJob(job);
      } else return;
    }
  }

  // Reserves capacity, increments concurrency, and submits the job to the executor.
  private synchronized void startJob(final MemoryLimitedJob job) {
    counter += job.initialAllocation;
    runningThreads++;
    if (LOG.isDebugEnabled()) LOG.debug("Starting job {}", job);
    executor.execute(
        new PrioRunnable() {

          @Override
          public void run() {
            MemoryLimitedChunk chunk =
                new MemoryLimitedChunk(MemoryLimitedJobRunner.this, job.initialAllocation);
            // If the job completes synchronously, release its allocation now.
            if (job.start(chunk)) chunk.release();
          }

          @Override
          public int getPriority() {
            return THREAD_PRIORITY;
          }
        });
  }

  /** For tests and stats: returns the current accounted usage. */
  long used() {
    return counter;
  }

  /**
   * Sets the maximum number of jobs allowed to run in parallel.
   *
   * <p>May cause queued jobs to start if additional slots become available.
   *
   * @param val new upper bound for concurrent jobs
   */
  public synchronized void setMaxThreads(int val) {
    this.maxThreads = val;
    maybeStartJobs();
  }

  /** Returns the current concurrency limit. */
  public synchronized int getMaxThreads() {
    return maxThreads;
  }

  /** Returns the capacity budget against which jobs are accounted. */
  public synchronized long getCapacity() {
    return capacity;
  }

  /**
   * Sets the capacity budget and reevaluates queued jobs.
   *
   * <p>Increasing capacity may admit queued jobs; decreasing it does not preempt running jobs but
   * will delay starting new ones until sufficient usage is released.
   *
   * @param val new capacity budget; units must match those used by queued jobs
   */
  public synchronized void setCapacity(long val) {
    capacity = val;
    maybeStartJobs();
  }

  /**
   * Initiates shutdown: prevents new jobs from being accepted.
   *
   * <p>Does not interrupt running jobs. Use {@link #waitForShutdown()} to block until all current
   * jobs finish and accounting drains to zero.
   */
  public synchronized void shutdown() {
    shutdown = true;
  }

  /**
   * Blocks until all currently running jobs have completed.
   *
   * <p>Semantics on interrupt: this method continues waiting even if the waiting thread is
   * interrupted. The interrupted status is recorded and restored on return so callers can observe
   * it afterward, but the shutdown contract (block until no jobs are running) is preserved.
   *
   * <p>This method does not throw {@link InterruptedException}. If the awaiting thread is
   * interrupted, the method records the interruption, continues waiting until all jobs finish, and
   * restores the interrupt status just before returning.
   */
  public synchronized void waitForShutdown() {
    shutdown = true;
    boolean interrupted = false;
    try {
      while (runningThreads > 0) {
        try {
          wait();
        } catch (InterruptedException _) {
          // Record and continue waiting until all jobs finish; restore status on exit.
          interrupted = true;
        }
      }
    } finally {
      if (interrupted) Thread.currentThread().interrupt();
    }
  }

  /** Returns the number of jobs currently running. */
  public synchronized int getRunningThreads() {
    return runningThreads;
  }
}

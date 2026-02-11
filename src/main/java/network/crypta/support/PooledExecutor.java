package network.crypta.support;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.node.PrioRunnable;
import network.crypta.support.io.NativeThread;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Lightweight, priority-aware executor that creates workers on demand and retires them after
 * inactivity.
 *
 * <p>Tasks that implement {@link PrioRunnable} contribute their own priority; other tasks run at
 * {@link NativeThread.PriorityLevel#NORM_PRIORITY}. Workers are created lazily when tasks are
 * submitted and exit after waiting up to {@link #TIMEOUT} milliseconds with no new work. When a
 * {@link Ticker} is configured and native priority adjustments are available, submissions that
 * require a higher priority than the caller's current priority may be delegated back to the ticker
 * to avoid priority inversion.
 *
 * <p>Thread-safety: All public methods are thread-safe. Introspection methods return snapshots that
 * may become stale immediately and are intended for diagnostics only.
 *
 * <p>Lifecycle: There is no explicit shutdown. Workers expire on their own when idle.
 *
 * @author toad
 */
public class PooledExecutor implements PriorityAwareExecutor {
  private static final Logger LOG = LoggerFactory.getLogger(PooledExecutor.class);

  /**
   * Counts of workers that exist per priority (running and waiting). Subtract the corresponding
   * waiting count to estimate actively running workers.
   */
  private final int[] runningThreads = new int[NativeThread.JAVA_PRIORITY_RANGE + 1];

  /** Per-priority stacks of idle workers (LIFO to favor cache locality). */
  private final List<ArrayList<MyThread>> waitingThreads = new ArrayList<>(runningThreads.length);

  private final java.util.concurrent.atomic.AtomicInteger waitingThreadsCount =
      new java.util.concurrent.atomic.AtomicInteger();
  AtomicLong[] threadCounter = new AtomicLong[runningThreads.length];
  private long jobCount;
  private long jobMisses;
  // Optional scheduler used to create threads at elevated priority when necessary.
  private Ticker ticker;

  /**
   * Set the optional scheduler used for delegation.
   *
   * <p>When present, the executor may delegate creation or execution of higher-priority work back
   * to the ticker when the submission originates outside the ticker context.
   *
   * @param ticker scheduler to use; {@code null} disables delegation
   */
  public synchronized void setTicker(Ticker ticker) {
    this.ticker = ticker;
  }

  /** Construct a new executor with empty per‑priority pools and counters. */
  public PooledExecutor() {
    for (int i = 0; i < runningThreads.length; i++) {
      waitingThreads.add(new ArrayList<>());
      threadCounter[i] = new AtomicLong();
    }
    waitingThreadsCount.set(0);
  }

  /** Maximum time a worker waits for a new job before exiting (milliseconds). */
  static final long TIMEOUT = MINUTES.toMillis(1);

  /**
   * No-op lifecycle hook kept for API compatibility.
   *
   * <p>PooledExecutor creates worker threads lazily on the first task submission and allows them to
   * expire after inactivity; there is no global start/shutdown state to initialize here.
   */
  public void start() {
    // Intentionally empty: threads are created lazily on submission.
  }

  /**
   * Submit a task for execution at the default priority.
   *
   * @param job the task to run; must be non-{@code null}
   * @throws IllegalArgumentException if {@code job} implements {@link PrioRunnable} and specifies
   *     an invalid priority
   */
  @Override
  public void execute(@NotNull Runnable job) {
    execute(job, "<noname>");
  }

  /**
   * Submit a labeled task at the default priority.
   *
   * @param job the task to run; must be non-{@code null}
   * @param jobName descriptive label used in logs and worker names; may be {@code null} or empty
   * @throws IllegalArgumentException if {@code job} implements {@link PrioRunnable} and specifies
   *     an invalid priority
   */
  @Override
  public void execute(Runnable job, String jobName) {
    execute(job, jobName, false);
  }

  /**
   * Submit a labeled task with an origin hint.
   *
   * <p>When {@code fromTicker} is {@code false} and a {@link Ticker} is configured, the executor
   * may delegate execution of tasks whose priority exceeds the caller's current priority back to
   * the ticker to avoid priority inversion.
   *
   * @param runnable the task to run; must be non-{@code null}
   * @param jobName descriptive label used in logs and worker names; may be {@code null} or empty
   * @param fromTicker {@code true} when called from the ticker to prevent delegation
   * @throws IllegalArgumentException if the inferred priority is outside the supported range
   */
  @Override
  public void execute(Runnable runnable, String jobName, boolean fromTicker) {
    final int prio = priorityOf(runnable);

    if (LOG.isDebugEnabled()) LOG.debug("Executing {} as {} at prio {}", runnable, jobName, prio);
    validatePriority(prio);

    final Job job = new Job(runnable, jobName);
    while (true) {
      MyThread t;
      boolean miss = false;
      synchronized (this) {
        jobCount++;
        t = removeWaitingThread(prio);
        if (t == null) {
          if (shouldDelegateToTicker(prio, fromTicker)) {
            ticker.queueTimedJob(runnable, jobName, 0, true, false);
            return;
          }
          miss = true;
        }
      }

      if (miss) {
        createAndStartWorker(job, prio, fromTicker, jobName);
        return;
      }

      if (t.tryAssignJob(job)) {
        logNotStarting(jobName);
        return;
      }
      // Otherwise, the chosen thread was not ready; retry.
    }
  }

  private static int priorityOf(Runnable runnable) {
    int prio = NativeThread.PriorityLevel.NORM_PRIORITY.value;
    if (runnable instanceof PrioRunnable prioRunnable) prio = prioRunnable.getPriority();
    return prio;
  }

  private static void validatePriority(int prio) {
    if (prio < NativeThread.PriorityLevel.MIN_PRIORITY.value
        || prio > NativeThread.PriorityLevel.MAX_PRIORITY.value)
      throw new IllegalArgumentException("Unrecognized priority level : " + prio + '!');
  }

  private MyThread removeWaitingThread(int prio) {
    ArrayList<MyThread> list = waitingThreads.get(prio - 1);
    if (!list.isEmpty()) {
      MyThread t = list.removeLast();
      if (t != null) waitingThreadsCount.decrementAndGet();
      if (LOG.isDebugEnabled()) LOG.debug("Reusing thread {}", t);
      return t;
    }
    return null;
  }

  private boolean shouldDelegateToTicker(int prio, boolean fromTicker) {
    return ticker != null
        && !fromTicker
        && NativeThread.usingNativeCode()
        && prio > Thread.currentThread().getPriority();
  }

  private void createAndStartWorker(Job job, int prio, boolean fromTicker, String jobName) {
    long threadNo = threadCounter[prio - 1].getAndIncrement();
    MyThread t =
        new MyThread(
            "Pooled thread awaiting work @" + threadNo + " for prio " + prio,
            job,
            threadNo,
            prio,
            !fromTicker);
    t.setDaemon(true);

    synchronized (this) {
      runningThreads[prio - 1]++;
      jobMisses++;

      if (LOG.isDebugEnabled())
        LOG.debug("Jobs: {} misses of {} starting urgently {}", jobMisses, jobCount, jobName);
    }

    t.start();
  }

  private void logNotStarting(String jobName) {
    if (LOG.isDebugEnabled())
      synchronized (this) {
        LOG.debug(
            "Not starting: Jobs: {} misses of {} starting urgently {}",
            jobMisses,
            jobCount,
            jobName);
      }
  }

  /**
   * Return counts of active workers per priority.
   *
   * <p>Each element equals the number of existing workers minus the number currently waiting for a
   * job.
   *
   * @return a new snapshot array with running counts per priority
   */
  @Override
  public synchronized int[] runningThreads() {
    int[] result = new int[runningThreads.length];
    for (int i = 0; i < result.length; i++)
      result[i] = runningThreads[i] - waitingThreads.get(i).size();
    return result;
  }

  /**
   * Return counts of idle workers per priority.
   *
   * @return a new snapshot array with waiting counts per priority
   */
  @Override
  public synchronized int[] waitingThreads() {
    int[] result = new int[waitingThreads.size()];
    for (int i = 0; i < result.length; i++) result[i] = waitingThreads.get(i).size();
    return result;
  }

  /**
   * Return the total number of idle workers across all priorities.
   *
   * @return total count of waiting workers
   */
  @Override
  public int getWaitingThreadsCount() {
    return waitingThreadsCount.get();
  }

  private static class Job {
    private final Runnable runnable;
    private final String name;
    private final int id;
    private static final java.util.concurrent.atomic.AtomicInteger JOB_ID_SEQ =
        new java.util.concurrent.atomic.AtomicInteger();

    Job(Runnable runnable, String name) {
      this.runnable = runnable;
      this.name = name;
      // Non-cryptographic, monotonic identifier used only for diagnostics/thread names
      this.id = JOB_ID_SEQ.incrementAndGet();
    }

    @SuppressWarnings("unused")
    public int getId() {
      return id;
    }
  }

  /** Immutable diagnostic sample for a worker thread. */
  public record DiagSample(int jobId, String name, long cpuTime) {}

  /**
   * Worker that executes tasks and returns to an idle state when finished.
   *
   * <p>Instances are created only by the enclosing executor. The class is {@code public} so
   * diagnostics can inspect job identifiers and thread names.
   */
  public class MyThread extends NativeThread {
    final String defaultName;
    volatile boolean alive = true;
    Job nextJob;
    final AtomicReference<Job> job = new AtomicReference<>();
    final long threadNo;
    private boolean removed = false;

    private MyThread(
        String defaultName, Job firstJob, long threadCounter, int prio, boolean dontCheckRenice) {
      super(defaultName, prio, dontCheckRenice);
      this.defaultName = defaultName;
      threadNo = threadCounter;
      nextJob = firstJob;
    }

    /** Execute the worker loop and decrement pool counters on exit. */
    @Override
    public void realRun() {
      int nativePriority = getNativePriority();
      try {
        innerRun(nativePriority);
      } finally {
        if (!removed) {
          synchronized (PooledExecutor.this) {
            runningThreads[nativePriority - 1]--;
          }
        }
      }
    }

    /**
     * Identifier used by diagnostics to group CPU time and names by logical job.
     *
     * @return the current job id if running, otherwise the next job id if assigned, or {@code 0}
     *     when none
     */
    public synchronized int getJobId() {
      Job currentJob = job.get();
      if (currentJob != null) return currentJob.id;
      if (nextJob != null) return nextJob.id;
      return 0;
    }

    /**
     * Take a consistent snapshot of this worker's current diagnostic identifiers under the worker's
     * monitor, aligning the job id with the current thread name.
     *
     * <p>Includes the current CPU time for this Java thread from {@link ManagementFactory}'s {@link
     * java.lang.management.ThreadMXBean} so callers can compute deltas keyed by job id.
     */
    public DiagSample diagSample() {
      synchronized (this) {
        int jid = getJobId();
        String nm = getName();
        long cpu = ManagementFactory.getThreadMXBean().getThreadCpuTime(this.threadId());
        return new DiagSample(jid, nm, cpu);
      }
    }

    /**
     * Main loop: run assigned jobs or wait up to {@link #TIMEOUT} for new work; exit on timeout.
     *
     * @param nativePriority priority bucket index used for counters
     */
    @SuppressWarnings("java:S1181")
    private void innerRun(int nativePriority) {
      long ranJobs = 0;
      while (true) {
        moveNextJobToCurrent();

        if (job.get() == null && onNoJobWaitAndMaybeExit(nativePriority, ranJobs)) return;
        Job currentJob = job.get();
        if (currentJob == null) continue;

        // Run the job
        try {
          setName(currentJob.name + "(" + threadNo + ")");
          currentJob.runnable.run();
        } catch (Throwable t) {
          LOG.error("Caught {} running job {}", t, currentJob, t);
        }
        ranJobs++;
      }
    }

    /**
     * Attempt to accept a job assignment.
     *
     * <p>Must be called by the pool under external synchronization; this method synchronizes on the
     * thread instance to avoid races with the worker lifecycle.
     */
    private boolean tryAssignJob(Job newJob) {
      synchronized (this) {
        if (!alive) return false;
        if (nextJob != null) return false;
        nextJob = newJob;
        // Use notifyAll() to avoid missing signals due to external synchronization.
        notifyAll();
        return true;
      }
    }

    /** Move any pending assignment into {@link #job} for execution. */
    private void moveNextJobToCurrent() {
      synchronized (this) {
        job.set(nextJob);
        nextJob = null;
      }
    }

    /**
     * Handle the idle path: register as waiting, wait with timeout, and decide whether to exit.
     *
     * @param nativePriority priority bucket index for counters
     * @param ranJobs number of jobs completed so far, used only for exit logging
     * @return {@code true} if the worker is exiting; {@code false} to continue execution
     */
    private boolean onNoJobWaitAndMaybeExit(int nativePriority, long ranJobs) {
      synchronized (PooledExecutor.this) {
        waitingThreads.get(nativePriority - 1).add(this);
        waitingThreadsCount.incrementAndGet();
      }
      synchronized (this) {
        long end = System.currentTimeMillis() + TIMEOUT;
        long remaining;
        boolean wasInterrupted = false;
        while (nextJob == null && (remaining = end - System.currentTimeMillis()) > 0) {
          this.setName(defaultName);
          try {
            wait(remaining);
          } catch (InterruptedException _) {
            // Preserve the interrupt status so higher levels can make an exit decision
            // (rule S2142: either rethrow or re‑interrupt). We choose to re‑interrupt and then
            // decide below whether to clear it when a job is actually present.
            Thread.currentThread().interrupt();
            wasInterrupted = true;
            break;
          }
        }
        if (wasInterrupted) {
          // We observed an interrupt while idle: clear the status unconditionally so that user
          // code never starts with an unexpected interrupted flag, regardless of whether a job is
          // already assigned now or will be assigned just after we release this monitor.
          // Capture the return value to satisfy static analysis (don’t ignore the result).
          boolean cleared = Thread.interrupted();
          if (LOG.isDebugEnabled()) {
            LOG.debug("Cleared interrupt status after idle interrupt (cleared={})", cleared);
          }
        }
      }
      synchronized (PooledExecutor.this) {
        if (waitingThreads.get(nativePriority - 1).remove(this))
          waitingThreadsCount.decrementAndGet();

        synchronized (this) {
          job.set(nextJob);
          nextJob = null;
          // Note: Some static analyzers flag this as double-checked locking; here we only
          // re-check after waiting to decide whether to exit the worker when no job arrived.
          if (job.get() == null) alive = false;
        }

        if (!alive) {
          runningThreads[nativePriority - 1]--;
          if (LOG.isDebugEnabled())
            LOG.debug("Exiting having executed {} jobs : {}", ranJobs, this);
          removed = true;
          return true;
        }
      }
      return false;
    }
  }
}

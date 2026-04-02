package network.crypta.support;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import network.crypta.node.PrioRunnable;
import network.crypta.support.io.NativeThread;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.MINUTES;

/**
 * Executor that guarantees tasks execute one after another on a single worker thread.
 *
 * <p>This executor queues submitted {@link Runnable} instances and processes them strictly in FIFO
 * order. It uses a real, backing {@link PriorityAwareExecutor} supplied via {@link #start} to run a
 * single long-lived "runner" task which drains the internal queue. The runner thread is not created
 * until {@link #start(PriorityAwareExecutor, String)} is called; submissions prior to that point
 * are queued and will run once started.
 *
 * <p>Priority: the runner implements {@link network.crypta.node.PrioRunnable} and reports the fixed
 * priority passed to this executor's constructor. Individual jobs do not influence the runner's
 * priority.
 *
 * <p>Queueing and capacity: jobs are stored in a {@link LinkedBlockingQueue}. When constructed with
 * a positive {@code bound}, the queue is bounded; additional submissions beyond capacity are
 * rejected by the queue and are dropped by this executor (a warning is logged). When unbounded,
 * submissions are only limited by memory.
 *
 * <p>Errors and exceptions thrown by jobs are caught and logged; processing continues with the next
 * job. The runner thread will exit when no job arrives for {@link #NEWJOB_TIMEOUT} milliseconds. A
 * new runner will be created automatically by future submissions.
 *
 * <p>Thread-safety: All public methods are thread-safe. Introspection methods return snapshots that
 * may become stale immediately after return and are intended for diagnostics only.
 */
public class SerialExecutor implements PriorityAwareExecutor {
  private static final Logger LOG = LoggerFactory.getLogger(SerialExecutor.class);

  // No static initialization required.

  /** Queue of submitted tasks. May be bounded or unbounded depending on constructor. */
  private final LinkedBlockingQueue<Runnable> jobs;

  private final Object syncLock;
  private final int priority;

  /** True when the runner is currently waiting for work (for introspection only). */
  private volatile boolean threadWaiting;

  /** True after a runner has been submitted to the backing executor (for introspection only). */
  private volatile boolean threadStarted;

  private String name;
  private PriorityAwareExecutor realExecutor;

  /** Maximum time (ms) the runner waits for a new job before exiting. */
  private static final long NEWJOB_TIMEOUT = MINUTES.toMillis(5);

  private Thread runningThread;

  /**
   * Runner task that drains {@link #jobs} sequentially.
   *
   * <p>It reports the configured priority via {@link PrioRunnable#getPriority()} so that the
   * backing {@link PriorityAwareExecutor} can schedule it accordingly. Interruptions while waiting
   * on the queue are recorded to honor the interruption and then cleared before returning the
   * thread to a pool to avoid leaking the interrupted status to unrelated tasks.
   */
  private final Runnable runner =
      new PrioRunnable() {

        @Override
        public int getPriority() {
          return priority;
        }

        @Override
        @SuppressWarnings("java:S1181")
        public void run() {
          boolean wasInterrupted = false;
          synchronized (syncLock) {
            runningThread = Thread.currentThread();
          }
          try {
            while (true) {
              synchronized (syncLock) {
                threadWaiting = true;
              }
              Runnable job = null;
              try {
                job = jobs.poll(NEWJOB_TIMEOUT, TimeUnit.MILLISECONDS);
              } catch (InterruptedException _) {
                // Preserve evidence of interruption as recommended by S2142, but we will clear it
                // before returning the thread to the pool to avoid leaking the flag.
                wasInterrupted = true;
                Thread.currentThread().interrupt();
              }
              synchronized (syncLock) {
                threadWaiting = false;
              }
              if (job == null) {
                synchronized (syncLock) {
                  threadStarted = false;
                }
                return;
              }

              try {
                job.run();
              } catch (Throwable t) {
                LOG.error("Caught {}", t, t);
                LOG.error("While running {} on {}", job, this);
              }
            }
          } finally {
            if (wasInterrupted) {
              // Clear the interrupted status before returning the underlying thread to the pool.
              final boolean hadInterrupt = Thread.interrupted();
              if (hadInterrupt && LOG.isDebugEnabled()) {
                LOG.debug("Cleared interrupt status on SerialExecutor runner");
              }
            }
            synchronized (syncLock) {
              runningThread = null;
            }
          }
        }
      };

  /**
   * Construct an executor with an unbounded queue.
   *
   * @param priority runner priority reported to the backing executor; usually one of {@link
   *     NativeThread.PriorityLevel} values
   */
  public SerialExecutor(int priority) {
    this(priority, 0);
  }

  /**
   * Construct an executor with an optional queue capacity.
   *
   * @param priority runner priority reported to the backing executor; usually one of {@link
   *     NativeThread.PriorityLevel} values
   * @param bound maximum number of queued jobs; {@code <= 0} creates an unbounded queue
   */
  public SerialExecutor(int priority, int bound) {
    if (bound > 0) jobs = new LinkedBlockingQueue<>(bound);
    else jobs = new LinkedBlockingQueue<>();
    this.priority = priority;
    this.syncLock = new Object();
  }

  /**
   * Wire this executor to a real backing executor and optionally start immediately.
   *
   * <p>If the internal queue is not empty when called, a runner is submitted to {@code
   * realExecutor} right away; otherwise a runner is created lazily on the first subsequent
   * submission. Passing {@code this} as {@code realExecutor} is not allowed.
   *
   * @param realExecutor backing executor used to run the single runner thread; must not be {@code
   *     this}
   * @param name human-readable label used in logs and the runner's thread name
   * @throws IllegalArgumentException if {@code realExecutor == this}
   */
  public void start(PriorityAwareExecutor realExecutor, String name) {
    if (realExecutor == this) {
      throw new IllegalArgumentException("realExecutor must not refer to this SerialExecutor");
    }
    this.realExecutor = realExecutor;
    this.name = name;
    synchronized (syncLock) {
      if (!jobs.isEmpty()) reallyStart();
    }
  }

  /** Submit the internal runner to the backing executor (caller holds {@link #syncLock}). */
  private void reallyStart() {
    synchronized (syncLock) {
      threadStarted = true;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Starting thread... {} : {}", name, runner);
    realExecutor.execute(runner, name);
  }

  /**
   * Submit a task with a default label.
   *
   * <p>The task is queued and will execute serially on the runner thread. If {@link #start} has not
   * yet been called, the task remains queued until a backing executor is provided. Exceptions and
   * {@link Error}s thrown by {@code job} are caught and logged.
   *
   * @param job task to execute; must be non-{@code null}
   */
  @Override
  public void execute(@NotNull Runnable job) {
    execute(job, "<noname>");
  }

  /**
   * Submit a task with a label for diagnostics.
   *
   * <p>The task is queued and will execute serially on the runner thread. When the queue is bounded
   * and full, the task is dropped and a warning is logged.
   *
   * @param job task to execute; must be non-{@code null}
   * @param jobName descriptive label used in logs; may be {@code null} or empty
   */
  @Override
  public void execute(Runnable job, String jobName) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Running {} : {} started={} waiting={}", jobName, job, threadStarted, threadWaiting);
    boolean offered = jobs.offer(job);
    if (!offered && LOG.isWarnEnabled()) {
      LOG.warn("SerialExecutor queue is full; dropping job {} ({})", jobName, job);
    }

    synchronized (syncLock) {
      if (!threadStarted && realExecutor != null) reallyStart();
    }
  }

  /**
   * Submit a task with a label and a ticker hint. The hint is ignored by this implementation.
   *
   * @param job task to execute; must be non-{@code null}
   * @param jobName descriptive label used in logs; may be {@code null} or empty
   * @param fromTicker ignored; retained for API compatibility
   */
  @Override
  public void execute(Runnable job, String jobName, boolean fromTicker) {
    execute(job, jobName);
  }

  /**
   * Return a snapshot of running worker counts per priority.
   *
   * <p>For {@code SerialExecutor} the value is either {@code 0} or {@code 1} at the configured
   * priority, depending on whether the runner is executing a job as opposed to waiting for one. The
   * array length equals {@code NativeThread.JAVA_PRIORITY_RANGE + 1}.
   *
   * @return array of running counts per priority (never {@code null})
   */
  @Override
  public int[] runningThreads() {
    int[] retval = new int[NativeThread.JAVA_PRIORITY_RANGE + 1];
    if (threadStarted && !threadWaiting) retval[priority] = 1;
    return retval;
  }

  /**
   * Return a snapshot of waiting worker counts per priority.
   *
   * <p>For {@code SerialExecutor} the value is either {@code 0} or {@code 1} at the configured
   * priority, depending on whether the runner is parked waiting for work. The array length equals
   * {@code NativeThread.JAVA_PRIORITY_RANGE + 1}.
   *
   * @return array of waiting counts per priority (never {@code null})
   */
  @Override
  public int[] waitingThreads() {
    int[] retval = new int[NativeThread.JAVA_PRIORITY_RANGE + 1];
    synchronized (syncLock) {
      if (threadStarted && threadWaiting) retval[priority] = 1;
    }
    return retval;
  }

  /**
   * Return the total number of waiting worker threads.
   *
   * <p>For {@code SerialExecutor} the value is {@code 0} or {@code 1}.
   *
   * @return number of waiting workers
   */
  @Override
  public int getWaitingThreadsCount() {
    synchronized (syncLock) {
      return (threadStarted && threadWaiting) ? 1 : 0;
    }
  }

  /**
   * Determine whether the current thread is the runner thread.
   *
   * @return {@code true} when called from the runner thread; {@code false} otherwise
   */
  public boolean onThread() {
    synchronized (syncLock) {
      return Thread.currentThread() == runningThread;
    }
  }
}

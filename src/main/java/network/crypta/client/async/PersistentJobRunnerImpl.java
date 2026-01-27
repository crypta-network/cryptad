package network.crypta.client.async;

import java.util.ArrayList;
import java.util.List;
import network.crypta.node.PrioRunnable;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Runs {@link PersistentJob} instances and periodically, or on demand, suspends all jobs to perform
 * a durable checkpoint via {@link #innerCheckpoint(boolean)}.
 *
 * <p>This runner coordinates execution and persistence for long‑lived client jobs that must survive
 * process restarts. It multiplexes tasks onto a {@link PriorityAwareExecutor} and consolidates
 * state changes into serialized checkpoints. Checkpoints are created at a configurable interval and
 * may also be triggered by jobs themselves or by explicit API calls.
 *
 * <p>The lifecycle is:
 *
 * <ol>
 *   <li>{@link #onLoading()} to indicate a state load is in progress.
 *   <li>{@link #onStarted(boolean)} to start accepting work and optionally enable writing.
 *   <li>Jobs are queued via {@link #queue(PersistentJob, int)} and {@link
 *       #queueInternal(PersistentJob)} while the runner schedules checkpointing in the background.
 *   <li>Shutdown flows call {@link #waitForIdleAndCheckpoint()} or {@link #shutdown()} followed by
 *       a final checkpoint.
 * </ol>
 *
 * <p>Concurrency model: job execution and checkpointing are mutually exclusive for persistence
 * safety. When a checkpoint is due, new work is queued, active work drains, and only then does the
 * runner invoke {@link #innerCheckpoint(boolean)} under a serialization lock. All externally
 * visible methods that mutate state synchronize on an internal monitor to preserve invariants. This
 * class is thread‑safe for its intended usage pattern.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Jobs requested during a checkpoint are queued and started immediately after it completes.
 *   <li>Checkpoint urgency can be escalated with {@link #setCheckpointASAP()} or by returning a
 *       checkpoint request from the job.
 *   <li>Shutdown waits for running jobs and any in‑flight checkpoint to complete before performing
 *       a final writing, unless writes are disabled.
 * </ul>
 *
 * @see PersistentJobRunner
 * @see PersistentJob
 * @see ClientContext
 * @see PriorityAwareExecutor
 * @see Ticker
 */
public abstract class PersistentJobRunnerImpl implements PersistentJobRunner {
  private static final Logger LOG = LoggerFactory.getLogger(PersistentJobRunnerImpl.class);

  final PriorityAwareExecutor executor;
  final Ticker ticker;

  /** The number of jobs actually running. */
  private int runningJobs;

  /** If true, we must suspend and write to disk. */
  private boolean mustCheckpoint;

  /** Jobs queued to run after the writing finishes. */
  private final List<QueuedJob> queuedJobs;

  private ClientContext context;
  private long lastCheckpointed;
  static final int WRITE_AT_PRIORITY = NativeThread.PriorityLevel.HIGH_PRIORITY.value - 1;
  final long checkpointInterval;

  /** Not to be used by child classes. */
  private final Object sync = new Object();

  /**
   * Mutex that serializes checkpoint operations across threads. Implementations must enter this
   * lock before performing any persistence work inside {@link #innerCheckpoint(boolean)} to ensure
   * that only one checkpoint is written at a time.
   */
  protected final Object serializeCheckpoints = new Object();

  private boolean willCheck = false;

  /** Have we enableCheckpointing the loading process? If so, we should accept jobs. */
  private boolean loading = false;

  /** Is checkpointing enabled at the moment? */
  private boolean enableCheckpointing = false;

  /** Have we loaded from disk at least once, regardless of enableCheckpointing? */
  private boolean loaded = false;

  /** True if a checkpoint is in progress */
  private boolean writing = false;

  /** True if we should reject all new jobs */
  private boolean killed = false;

  /**
   * Creates a new runner.
   *
   * @param executor the priority‑aware executor used to run jobs; must accept tasks immediately and
   *     honor the provided thread priority where supported.
   * @param ticker a timer facility used to schedule delayed checkpoint attempts; must be
   *     thread‑safe and deliver callbacks on a background thread.
   * @param interval the preferred checkpoint interval in milliseconds; actual timing may be later
   *     if work is still running when the interval elapses.
   */
  protected PersistentJobRunnerImpl(PriorityAwareExecutor executor, Ticker ticker, long interval) {
    this.executor = executor;
    this.ticker = ticker;
    queuedJobs = new ArrayList<>();
    lastCheckpointed = System.currentTimeMillis();
    this.checkpointInterval = interval;
  }

  /**
   * Binds the runner to a client context and prepares it for accepting work.
   *
   * <p>This method must be called before queueing jobs. It does not enable checkpointing by itself;
   * call {@link #onStarted(boolean)} after any initial load to begin normal operation.
   *
   * @param context the client context passed to each job; must not be {@code null}.
   */
  public void start(ClientContext context) {
    synchronized (sync) {
      this.context = context;
    }
  }

  /** {@inheritDoc} */
  @Override
  public void queue(PersistentJob job, int threadPriority) throws PersistenceDisabledException {
    synchronized (sync) {
      if (!loading) throw new PersistenceDisabledException();
      if (killed) throw new PersistenceDisabledException();
      if (context == null) throw new IllegalStateException();
      if (mustCheckpoint && enableCheckpointing) {
        if (LOG.isTraceEnabled()) LOG.trace("Queueing job {}", job);
        queuedJobs.add(new QueuedJob(job, threadPriority));
      } else {
        if (LOG.isTraceEnabled()) LOG.trace("Dispatching queued job {}", job);
        executor.execute(new JobRunnable(job, threadPriority, context));
        runningJobs++;
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void queueInternal(PersistentJob job, int threadPriority)
      throws PersistenceDisabledException {
    synchronized (sync) {
      if (!loading) throw new PersistenceDisabledException();
      if (killed) throw new PersistenceDisabledException();
      if (context == null) throw new IllegalStateException();
      if (writing) {
        LOG.error(
            "Internal job must not be queued during writing! They should have finished before we"
                + " start writing and cannot be started \"externally\"!",
            new Exception("error"));
        queuedJobs.add(new QueuedJob(job, threadPriority));
      } else {
        if (mustCheckpoint && LOG.isDebugEnabled()) LOG.debug("Deferring checkpoint until idle");
        runningJobs++;
        if (LOG.isTraceEnabled()) LOG.trace("Dispatching internal job {}", job);
        executor.execute(new JobRunnable(job, threadPriority, context));
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public void queueInternal(PersistentJob job) {
    try {
      queueInternal(job, NativeThread.PriorityLevel.NORM_PRIORITY.value);
    } catch (PersistenceDisabledException e) {
      // Maybe this could happen ... panic button maybe?
      LOG.error("Dropping internal job; persistence disabled: {}", e, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void queueNormalOrDrop(PersistentJob job) {
    try {
      queue(job, NativeThread.PriorityLevel.NORM_PRIORITY.value);
    } catch (PersistenceDisabledException _) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Dropping queued job; persistence disabled: {}", job);
      }
    }
  }

  private class JobRunnable implements Runnable {

    private final int threadPriority;
    private final PersistentJob job;
    private final ClientContext context;

    public JobRunnable(PersistentJob job, int threadPriority, ClientContext context) {
      this.job = job;
      this.threadPriority = threadPriority;
      this.context = context;
    }

    @Override
    public void run() {
      boolean ret = false;
      try {
        if (LOG.isTraceEnabled()) LOG.trace("Starting {}", job);
        ret = job.run(context);
      } catch (Exception e) {
        LOG.error("Caught exception running job {}", job, e);
      } finally {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Completed {} with mustCheckpoint={} enableCheckpointing={} runningJobs={}",
              job,
              mustCheckpoint,
              enableCheckpointing,
              runningJobs);
        handleCompletion(ret, threadPriority);
      }
    }
  }

  /**
   * Handles completion of a job and coordinates any pending checkpoint.
   *
   * <p>Decrements the count of running jobs, evaluates whether a checkpoint is due based on the
   * job's return value and elapsed time, and either triggers a checkpoint immediately or schedules
   * a delayed attempt. When a checkpoint is needed, new jobs are deferred until after the writing.
   *
   * @param ret {@code true} when the completed job requests a checkpoint; {@code false} otherwise.
   * @param threadPriority the priority of the thread that executed the job. Higher values indicate
   *     higher priority and may influence whether the checkpoint runs inline or off‑thread.
   */
  public void handleCompletion(boolean ret, int threadPriority) {
    synchronized (sync) {
      runningJobs--;
      if (runningJobs == 0)
        // Even if not going to the checkpoint indirectly, somebody might be waiting, need to
        // notify.
        sync.notifyAll();
      if (!enableCheckpointing) {
        if (LOG.isDebugEnabled()) LOG.debug("Not enableCheckpointing yet");
        return;
      }
      maybeSetCheckpointFlag(ret);
      if (!mustCheckpoint) {
        delayedCheckpoint();
        return;
      }
      if (runningJobs != 0) {
        if (LOG.isTraceEnabled()) LOG.trace("Not writing yet");
        return;
      }
      if (!killed) {
        writing = true;
        if (threadPriority < WRITE_AT_PRIORITY) {
          checkpointOffThread();
          return;
        }
      }
    }
    checkpoint(false);
  }

  private void maybeSetCheckpointFlag(boolean jobRequestedCheckpoint) {
    if (jobRequestedCheckpoint) {
      mustCheckpoint = true;
      if (LOG.isDebugEnabled()) LOG.debug("Scheduling checkpoint; job requested");
    }
    if (!mustCheckpoint && (System.currentTimeMillis() - lastCheckpointed > checkpointInterval)) {
      mustCheckpoint = true;
      if (LOG.isDebugEnabled()) LOG.debug("Scheduling checkpoint; interval elapsed");
    }
  }

  private record QueuedJob(PersistentJob job, int threadPriority) {}

  private void checkpoint(boolean shutdown) {
    if (LOG.isDebugEnabled()) LOG.debug("Writing checkpoint...");
    synchronized (sync) {
      if (!enableCheckpointing) {
        writing = false;
        sync.notifyAll();
        return;
      }
    }
    synchronized (serializeCheckpoints) {
      try {
        innerCheckpoint(shutdown);
      } catch (Exception t) {
        LOG.error("Unable to save", t);
      }
    }
    synchronized (sync) {
      mustCheckpoint = false;
      writing = false;
      QueuedJob[] jobs = queuedJobs.toArray(new QueuedJob[0]);
      if (LOG.isTraceEnabled()) LOG.trace("Starting {} queued jobs", jobs.length);
      for (QueuedJob job : jobs) {
        runningJobs++;
        executor.execute(new JobRunnable(job.job, job.threadPriority, context));
      }
      updateLastCheckpointed();
      queuedJobs.clear();
      sync.notifyAll();
    }
    if (LOG.isDebugEnabled()) LOG.debug("Completed writing checkpoint");
  }

  /**
   * Schedules a delayed checkpoint attempt based on {@code checkpointInterval}.
   *
   * <p>If checkpointing is disabled, a checkpoint is already pending, or work is running, this call
   * becomes a no‑op. When the timer fires and the runner is idle, a checkpoint is performed on a
   * high‑priority thread.
   */
  public void delayedCheckpoint() {
    synchronized (sync) {
      if (killed || !enableCheckpointing) return;
      if (willCheck) return;
      ticker.queueTimedJob(
          new PrioRunnable() {

            @Override
            public void run() {
              synchronized (sync) {
                willCheck = false;
                if (!(mustCheckpoint
                    || System.currentTimeMillis() - lastCheckpointed > checkpointInterval)) return;
                if (killed || !enableCheckpointing) return;
                if (runningJobs != 0) return;
                writing = true;
              }
              checkpoint(false);
            }

            @Override
            public int getPriority() {
              return WRITE_AT_PRIORITY;
            }
          },
          checkpointInterval);
      willCheck = true;
    }
  }

  /**
   * Triggers a checkpoint on a background thread, returning immediately.
   *
   * <p>If checkpointing is disabled or shutdown has been requested in the interim, the request is
   * ignored. This method is useful when the caller is running at a lower priority than the
   * dedicated checkpoint priority.
   */
  public void checkpointOffThread() {
    executor.execute(
        new PrioRunnable() {

          @Override
          public void run() {
            synchronized (sync) {
              if (killed || !enableCheckpointing) {
                writing = false;
                sync.notifyAll();
                return;
              }
            }
            checkpoint(false);
          }

          @Override
          public int getPriority() {
            return WRITE_AT_PRIORITY;
          }
        });
  }

  /**
   * Requests that a checkpoint be performed as soon as possible.
   *
   * <p>If no jobs are currently running and checkpointing is enabled, a background checkpoint is
   * queued immediately. Otherwise, the request is remembered and honored when the runner becomes
   * idle.
   */
  @Override
  public void setCheckpointASAP() {
    synchronized (sync) {
      if (!enableCheckpointing) return;
      mustCheckpoint = true;
      if (runningJobs != 0) return;
    }
    checkpointOffThread();
  }

  /**
   * Updates the internal {@code lastCheckpointed} timestamp.
   *
   * <p>Subclasses may override to record additional metadata, but must call {@code super} to keep
   * interval accounting accurate.
   */
  protected void updateLastCheckpointed() {
    lastCheckpointed = System.currentTimeMillis();
  }

  /**
   * Writes a persistence checkpoint of the current runner state.
   *
   * <p>Implementations must perform all I/O within the {@link #serializeCheckpoints} monitor and
   * should avoid blocking unrelated threads. Any exception thrown from this method is caught and
   * logged by the caller and does not abort the runner.
   *
   * @param shutdown {@code true} when called from an explicit shutdown path; implementations may
   *     choose to perform additional flushing or integrity validation when shutting down.
   */
  protected abstract void innerCheckpoint(boolean shutdown);

  /**
   * Marks the beginning of state loading.
   *
   * <p>After calling this method the runner will accept jobs, but depending on configuration may
   * defer checkpointing until {@link #onStarted(boolean)} is invoked.
   */
  protected void onLoading() {
    synchronized (sync) {
      loading = true;
    }
  }

  /**
   * Transitions the runner to the started state.
   *
   * @param noWrite when {@code true}, starts without enabling checkpointing; when {@code false},
   *     enables checkpointing and schedules an initial background writing.
   */
  protected void onStarted(boolean noWrite) {
    synchronized (sync) {
      loading = true;
      if (!noWrite) enableCheckpointing = true;
      loaded = true;
      updateLastCheckpointed();
      writing = true;
    }
    checkpointOffThread();
  }

  /**
   * Requests shutdown of the runner.
   *
   * <p>New jobs are rejected after this call. Use {@link #waitForIdleAndCheckpoint()} to wait for
   * running work to drain and to perform a final checkpoint before the process exits.
   */
  public void shutdown() {
    synchronized (sync) {
      killed = true;
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean shuttingDown() {
    synchronized (sync) {
      return killed;
    }
  }

  /**
   * Typically called after shutdown() to wait for current jobs to complete. Does not check killed
   * for this reason.
   */
  public void waitForIdleAndCheckpoint() {
    synchronized (sync) {
      while (runningJobs > 0 || writing) {
        if (!enableCheckpointing) return;
        if (LOG.isInfoEnabled()) {
          LOG.info("Waiting to shutdown: {} running{}", runningJobs, (writing ? " (writing)" : ""));
        }
        try {
          sync.wait();
        } catch (InterruptedException _) {
          Thread.currentThread().interrupt();
          return;
        }
      }
    }
    checkpoint(true);
  }

  /**
   * Wait until a checkpoint has been completed, or if the job runner becomes idle, do it here.
   *
   * @throws PersistenceDisabledException thrown if checkpointing is disabled or shutdown has been
   *     requested while waiting, or the wait is interrupted; callers should treat this as a signal
   *     that no checkpoint will be performed by this invocation.
   */
  public void waitAndCheckpoint() throws PersistenceDisabledException {
    synchronized (sync) {
      if (!enableCheckpointing) return;
      // Set a flag to ensure further jobs are queued, we want to write soon!
      mustCheckpoint = true;
      waitForRunningJobs();
      if (writing) {
        waitWhileWriting();
        return;
      }
      writing = true;
    }
    checkpoint(true);
  }

  private void waitForRunningJobs() throws PersistenceDisabledException {
    while (runningJobs > 0) {
      if (!enableCheckpointing) return;
      if (killed) throw new PersistenceDisabledException();
      LOG.error("Waiting for {} to finish before checkpoint", runningJobs);
      try {
        synchronized (sync) {
          sync.wait();
        }
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
        throw new PersistenceDisabledException();
      }
    }
  }

  private void waitWhileWriting() throws PersistenceDisabledException {
    while (writing) {
      if (!enableCheckpointing) return;
      if (killed) throw new PersistenceDisabledException();
      try {
        synchronized (sync) {
          sync.wait();
        }
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
        throw new PersistenceDisabledException();
      }
    }
  }

  /**
   * Sets the killed flag and blocks until no checkpoint is in progress.
   *
   * <p>Callers use this during shutdown to ensure that any ongoing writing completes before
   * continuing with teardown logic. This method does not perform a new checkpoint.
   */
  protected void killAndWaitForNotWriting() {
    synchronized (sync) {
      killed = true;
      while (writing) {
        try {
          sync.wait();
        } catch (InterruptedException _) {
          Thread.currentThread().interrupt();
          return;
        }
      }
    }
  }

  /**
   * Blocks the caller while a checkpoint is in progress.
   *
   * <p>Returns immediately when no checkpoint is running. The method is interruptible and restores
   * the interrupted status on the current thread if awakened prematurely.
   */
  public void waitForNotWriting() {
    synchronized (sync) {
      while (writing) {
        try {
          sync.wait();
        } catch (InterruptedException _) {
          Thread.currentThread().interrupt();
          return;
        }
      }
    }
  }

  /**
   * Sets the killed flag and waits for all running jobs and any checkpoint to complete.
   *
   * <p>Unlike {@link #waitForIdleAndCheckpoint()}, this method does not initiate a new checkpoint
   * after draining. It is intended for callers that want a hard stop without additional writes.
   */
  public void killAndWaitForNotRunning() {
    synchronized (sync) {
      killed = true;
      while (runningJobs > 0 || writing) {
        try {
          sync.wait();
        } catch (InterruptedException _) {
          Thread.currentThread().interrupt();
          return;
        }
      }
    }
  }

  /**
   * Returns whether the runner is killed or has not completed its first load.
   *
   * @return {@code true} when shutdown has been requested or the initial load has not yet
   *     completed; {@code false} otherwise.
   */
  public boolean isKilledOrNotLoaded() {
    synchronized (sync) {
      return killed || !loaded;
    }
  }

  /**
   * Indicates whether the runner has completed loading persisted state at least once.
   *
   * @return {@code true} after {@link #onStarted(boolean)} has been invoked following a load;
   *     {@code false} otherwise.
   */
  @Override
  public boolean hasLoaded() {
    synchronized (sync) {
      return loaded;
    }
  }

  /**
   * Returns the current {@link ClientContext} used for executing jobs.
   *
   * @return the non‑null context previously passed to {@link #start(ClientContext)}; intended for
   *     subclass use when implementing higher‑level coordination.
   */
  protected ClientContext getClientContext() {
    return context;
  }

  /**
   * Acquires a lock that prevents checkpointing while the caller performs a critical section.
   *
   * <p>The returned {@link CheckpointLock} must be closed to signal completion. While held, no
   * checkpoint will start; the caller is counted as a running job.
   *
   * @return a lock handle; closing it decrements the running job count and re‑evaluates the need
   *     for a checkpoint.
   * @throws PersistenceDisabledException if shutdown has been requested or checkpointing is
   *     disabled while attempting to acquire the lock.
   */
  @Override
  public CheckpointLock lock() throws PersistenceDisabledException {
    synchronized (sync) {
      if (killed) throw new PersistenceDisabledException();
      while (writing || (mustCheckpoint && enableCheckpointing)) {
        try {
          sync.wait();
        } catch (InterruptedException _) {
          Thread.currentThread().interrupt();
          throw new PersistenceDisabledException();
        }
        if (killed) throw new PersistenceDisabledException();
      }
      runningJobs++;
    }
    return this::handleCompletion;
  }

  /**
   * Disables checkpointing and clears any pending checkpoint request.
   *
   * <p>Waiting threads are notified. New or running jobs will proceed without triggering
   * persistence until checkpointing is re‑enabled by the owning component.
   */
  public void disableWrite() {
    synchronized (sync) {
      enableCheckpointing = false;
      mustCheckpoint = false;
      sync.notifyAll();
    }
  }

  boolean mustCheckpoint() {
    synchronized (sync) {
      return mustCheckpoint;
    }
  }
}

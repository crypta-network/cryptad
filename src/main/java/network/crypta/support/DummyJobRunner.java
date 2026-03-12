package network.crypta.support;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.PersistentJobRunner;
import network.crypta.node.PrioRunnable;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Non-persistent implementation of {@link PersistentJobRunner}.
 *
 * <p>This runner submits jobs directly to a provided {@link PriorityAwareExecutor} and does not
 * coordinate checkpointing, persistence, or loading phases. It is useful for transient or
 * best-effort work where saving client-layer state is unnecessary. Using this avoids sprinkling
 * callers with {@code if (persistent) ...} checks.
 *
 * <p>Threading: Jobs are executed on the given executor and therefore usually run off the calling
 * thread. Jobs are wrapped in a {@link PrioRunnable} so priority-aware executors can read the
 * requested priority. No internal queueing or locking is performed beyond the executor submission.
 *
 * <p>Persistence: Methods related to checkpointing and lifecycle (e.g., {@link #setCheckpointASAP}
 * and {@link #lock()}) are effectively no-ops; {@link #hasLoaded()} always returns {@code true}.
 */
public class DummyJobRunner implements PersistentJobRunner {
  private static final Logger LOG = LoggerFactory.getLogger(DummyJobRunner.class);

  final PriorityAwareExecutor executor;
  final ClientContext context;

  /**
   * Create a dummy job runner.
   *
   * @param executor executor used to run submitted jobs; must tolerate {@link PrioRunnable}
   *     instances
   * @param context {@link ClientContext} passed to each job's {@link
   *     PersistentJob#run(ClientContext)}; may be {@code null}
   */
  public DummyJobRunner(PriorityAwareExecutor executor, ClientContext context) {
    this.executor = executor;
    this.context = context;
  }

  /**
   * Submit a job immediately to the executor.
   *
   * <p>No persistence checks occur. The job is executed in the executor's thread and the supplied
   * {@code priority} is exposed via {@link PrioRunnable#getPriority()}.
   *
   * @param job task to run; must be non-null
   * @param priority priority hint for the executor
   */
  @Override
  public void queue(final PersistentJob job, final int priority) {
    if (LOG.isDebugEnabled()) LOG.debug("Running job off thread: {}", job);
    executor.execute(
        new PrioRunnable() {

          @Override
          public void run() {
            if (LOG.isDebugEnabled()) LOG.debug("Starting job {}", job);
            job.run(context);
          }

          @Override
          public int getPriority() {
            return priority;
          }
        });
  }

  /**
   * Submit a job at {@link NativeThread.PriorityLevel#NORM_PRIORITY}.
   *
   * <p>This dummy implementation never drops jobs; it simply forwards to {@link #queue} with normal
   * priority.
   *
   * @param job task to run
   */
  @Override
  public void queueNormalOrDrop(PersistentJob job) {
    queue(job, NativeThread.PriorityLevel.NORM_PRIORITY.value);
  }

  /**
   * No-op.
   *
   * <p>Persistent implementations would request an immediate checkpoint; this runner does not
   * checkpoint.
   */
  @Override
  public void setCheckpointASAP() {
    // Intentionally ignored: there is no checkpointing in this implementation.
  }

  /**
   * The dummy runner is always considered loaded.
   *
   * @return {@code true}
   */
  @Override
  public boolean hasLoaded() {
    return true;
  }

  /**
   * Submit an internal job with the given priority.
   *
   * <p>For the dummy runner, internal jobs behave the same as regular jobs.
   *
   * @param job task to run
   * @param threadPriority priority hint for the executor
   */
  @Override
  public void queueInternal(PersistentJob job, int threadPriority) {
    queue(job, threadPriority);
  }

  /**
   * Submit an internal job at {@link NativeThread.PriorityLevel#NORM_PRIORITY}.
   *
   * @param job task to run
   */
  @Override
  public void queueInternal(PersistentJob job) {
    queueInternal(job, NativeThread.PriorityLevel.NORM_PRIORITY.value);
  }

  /**
   * Return a lock whose {@code unlock(...)} method is a no-op.
   *
   * <p>Persistent implementations would use this to defer checkpointing while a job updates state.
   * The dummy runner never checkpoints and therefore the returned lock does nothing.
   *
   * @return a no-op {@link CheckpointLock}
   */
  @Override
  public CheckpointLock lock() {
    return (forceWrite, threadPriority) -> {
      // No-op: checkpointing is not supported here.
    };
  }

  /**
   * Always returns {@code false}; the dummy runner does not load persistent requests.
   *
   * @return {@code false}
   */
  @Override
  public boolean newSalt() {
    return false;
  }

  /**
   * Always returns {@code false}; the dummy runner does not manage shutdown state.
   *
   * @return {@code false}
   */
  @Override
  public boolean shuttingDown() {
    return false;
  }
}

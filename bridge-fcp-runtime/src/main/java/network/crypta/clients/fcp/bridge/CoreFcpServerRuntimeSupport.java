package network.crypta.clients.fcp.bridge;

import java.util.Objects;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.PersistentJobRunner;
import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import network.crypta.clients.fcp.FcpPersistentJob;
import network.crypta.clients.fcp.FcpServerRuntimeSupport;
import network.crypta.node.NodeClientCore;
import network.crypta.support.api.BucketFactory;

/**
 * Core-backed implementation of {@link FcpServerRuntimeSupport}.
 *
 * <p>This adapter keeps the server-owned FCP infrastructure coupled to a narrow runtime-support
 * contract instead of directly to {@link NodeClientCore}. It is an immutable wrapper over the live
 * daemon core and delegates each method directly so connection handlers, persistent ops, and the
 * parser continue to observe the current runtime state.
 *
 * <p>Callers typically get a single instance from the runtime-owned FCP bootstrap wiring during
 * server construction and reuse it for the lifetime of that server. The record does not cache
 * derived state, so every method reflects the current core-backed factories, context, and
 * persistence status at the time of the call. That keeps the seam narrow and reversible while still
 * preserving the same operational behavior that the pre-refactor code saw through direct core
 * access.
 *
 * @param core live daemon core backing the owning FCP server
 */
record CoreFcpServerRuntimeSupport(NodeClientCore core) implements FcpServerRuntimeSupport {

  /**
   * Creates a runtime-support adapter backed by the supplied node core.
   *
   * <p>The constructor retains the live core reference rather than copying out individual services.
   * That choice ensures later calls still see the current client context, bucket factories, and
   * persistence state owned by the daemon. The provided core must therefore already be fully
   * initialized for normal FCP server operation.
   *
   * @param core live daemon core that owns the runtime services exposed through this seam
   * @throws NullPointerException if {@code core} is {@code null}
   */
  CoreFcpServerRuntimeSupport(NodeClientCore core) {
    this.core = Objects.requireNonNull(core);
  }

  @Override
  public ClientContext clientContext() {
    return core.getClientContext();
  }

  /**
   * Returns the detached persistence-runtime context for server-side bridge helpers.
   *
   * <p>The returned context is still the live client context at runtime, but adapter-side code can
   * depend on the narrower {@link PersistentRequestRuntimeContext} seam when it only needs to
   * schedule persistent work or resume durable requests.
   *
   * @return detached persistence-runtime context backed by the live client context
   */
  @Override
  public PersistentRequestRuntimeContext persistentRequestRuntimeContext() {
    return core.getClientContext();
  }

  /**
   * Queues a detached persistent job on the live job runner.
   *
   * <p>This keeps the bridge-owned mapping from detached server work back to the live {@link
   * PersistentJobRunner} while allowing server-side code to stop importing the runtime job type
   * directly.
   *
   * @param job detached persistent job to queue
   * @param threadPriority thread priority used for the live runner submission
   * @throws PersistenceDisabledException if the underlying job runner cannot accept work
   */
  @Override
  public void queuePersistentJob(FcpPersistentJob job, int threadPriority)
      throws PersistenceDisabledException {
    ClientContext clientContext = clientContext();
    clientContext.jobRunner.queue(new CorePersistentJob(job), threadPriority);
  }

  /**
   * Requests an early checkpoint on the live persistent job runner.
   *
   * <p>Bridge code uses this for the same checkpoint-as-soon-as-possible behavior the adapter used
   * to trigger by reaching through the live client context directly.
   */
  @Override
  public void setCheckpointASAP() {
    clientContext().jobRunner.setCheckpointASAP();
  }

  @Override
  public boolean persistenceDisabled() {
    return core.killedDatabase();
  }

  @Override
  public BucketFactory tempBucketFactory() {
    return core.getTempBucketFactory();
  }

  @Override
  public BucketFactory persistentTempBucketFactory() {
    return core.getPersistentTempBucketFactory();
  }

  @Override
  public void fillSecureRandom(byte[] bytes) {
    core.getRandom().nextBytes(bytes);
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class CorePersistentJob implements PersistentJob {
    private final FcpPersistentJob job;

    private CorePersistentJob(FcpPersistentJob job) {
      this.job = Objects.requireNonNull(job);
    }

    @Override
    public boolean run(ClientContext context) {
      return job.run(context);
    }

    @Override
    public String toString() {
      return job.toString();
    }
  }
}

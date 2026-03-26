package network.crypta.runtime.endpoints.fcp;

import java.util.Objects;
import network.crypta.client.async.ClientContext;
import network.crypta.clients.fcp.FcpServerRuntimeSupport;
import network.crypta.node.NodeClientCore;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.PersistentTempBucketFactory;

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

  @Override
  public boolean persistenceDisabled() {
    return core.killedDatabase();
  }

  @Override
  public BucketFactory tempBucketFactory() {
    return core.getTempBucketFactory();
  }

  @Override
  public PersistentTempBucketFactory persistentTempBucketFactory() {
    return core.getPersistentTempBucketFactory();
  }

  @Override
  public void fillSecureRandom(byte[] bytes) {
    core.getRandom().nextBytes(bytes);
  }
}

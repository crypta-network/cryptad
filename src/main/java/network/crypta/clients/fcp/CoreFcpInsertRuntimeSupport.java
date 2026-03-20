package network.crypta.clients.fcp;

import java.io.IOException;
import java.util.Objects;
import java.util.function.Supplier;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.USKManager;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;

/**
 * Core-backed implementation of {@link FcpInsertRuntimeSupport}.
 *
 * <p>This adapter is the insert/USK assembly seam between {@code clients.fcp} and the broader
 * daemon runtime. It keeps insert-specific wiring local to this package by translating the small
 * set of insert dependencies into direct delegations on the wrapped {@link NodeClientCore} plus the
 * transfer-access policy supplier used for upload validation. The adapter is immutable after
 * construction and observes the live daemon state on each call.
 *
 * @param core live daemon core used for insert contexts, bucket allocation, and USK subscriptions
 * @param transferAccessSupplier live transfer-policy lookup used for upload DDA checks; callers
 *     typically bind this to {@code core.getRuntimePorts().transferAccess()} to preserve legacy
 *     insert validation behavior
 */
record CoreFcpInsertRuntimeSupport(
    NodeClientCore core, Supplier<TransferAccessPort> transferAccessSupplier)
    implements FcpInsertRuntimeSupport {

  /**
   * Creates an insert-runtime adapter over the supplied live daemon services.
   *
   * <p>The adapter does not snapshot state. Later calls continue to observe the current client
   * context, bucket factories, USK manager, and transfer policy exposed by the wrapped core and the
   * supplied transfer-policy lookup. Callers usually construct one instance per {@link FCPServer}
   * and reuse it for all insert and USK request assembly in that server.
   *
   * @param core live daemon core providing insert contexts, persistent bucket factories, and USK
   *     services for the FCP insert path
   * @param transferAccessSupplier live transfer-policy lookup that should stay aligned with the
   *     legacy insert validation policy while requests are being created
   */
  CoreFcpInsertRuntimeSupport(
      NodeClientCore core, Supplier<TransferAccessPort> transferAccessSupplier) {
    this.core = Objects.requireNonNull(core);
    this.transferAccessSupplier = Objects.requireNonNull(transferAccessSupplier);
  }

  @Override
  public ClientContext clientContext() {
    return core.getClientContext();
  }

  @Override
  public InsertContext defaultPersistentInsertContext() {
    return core.getClientContext().getDefaultPersistentInsertContext();
  }

  @Override
  public TransferAccessPort transferAccess() {
    return Objects.requireNonNull(transferAccessSupplier.get());
  }

  @Override
  public BucketFactory bucketFactory(boolean persistentForever) {
    return core.getClientContext().getBucketFactory(persistentForever);
  }

  @Override
  public RandomAccessBucket allocatePersistentUploadBucket(long length)
      throws IOException, PersistenceDisabledException {
    if (core.killedDatabase()) {
      throw new PersistenceDisabledException();
    }
    return core.getPersistentTempBucketFactory().makeBucket(length);
  }

  @Override
  public USKManager uskManager() {
    return core.getUskManager();
  }
}

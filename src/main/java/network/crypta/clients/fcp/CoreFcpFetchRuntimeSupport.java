package network.crypta.clients.fcp;

import java.io.IOException;
import java.util.Objects;
import network.crypta.client.FetchContext;
import network.crypta.client.async.ClientContext;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.api.Bucket;

/**
 * Core-backed implementation of {@link FcpFetchRuntimeSupport}.
 *
 * <p>This adapter is the GET-path assembly seam between {@code clients.fcp} and the broader daemon
 * runtime. It keeps the fetch-specific wiring local to this package by translating the small set of
 * GET dependencies into direct delegations on the wrapped {@link NodeClientCore} plus the owning
 * server's transfer-access policy. The adapter is immutable after construction and observes the
 * live daemon state on each call.
 *
 * <p>The split between {@code core} and {@code transferAccess} is intentional. Fetch creation still
 * needs the live client context and bucket factories from the daemon core, while DDA checks and
 * default download locations must remain aligned with the {@link FCPServer} runtime that owns the
 * request flow. Keeping both collaborators here preserves that behavior without letting the GET
 * classes depend on {@code NodeClientCore} directly.
 *
 * @param core live daemon core used for fetch contexts, client starts, and bucket allocation
 * @param transferAccess transfer policy from the owning server runtime, used for DDA checks and
 *     download-path defaults
 */
record CoreFcpFetchRuntimeSupport(NodeClientCore core, TransferAccessPort transferAccess)
    implements FcpFetchRuntimeSupport {

  /**
   * Creates a fetch runtime adapter for the supplied node core.
   *
   * <p>The adapter is a thin wrapper and does not snapshot mutable daemon state. Later method calls
   * continue to observe the live client context and bucket factories exposed by {@code core}, while
   * transfer checks continue to use the server-owned {@code transferAccess} instance passed here.
   *
   * @param core live daemon core providing fetch contexts and bucket allocation
   * @param transferAccess transfer policy from the owning server runtime, used for DDA checks and
   *     default download locations
   */
  CoreFcpFetchRuntimeSupport(NodeClientCore core, TransferAccessPort transferAccess) {
    this.core = Objects.requireNonNull(core);
    this.transferAccess = Objects.requireNonNull(transferAccess);
  }

  /**
   * Returns the live client context from the wrapped daemon core.
   *
   * <p>GET requests use this context when they start or resume execution. The adapter does not
   * cache or clone the value, so callers observe the same live context the core currently exposes.
   *
   * @return current client context used for FCP fetch execution
   */
  @Override
  public ClientContext clientContext() {
    return core.getClientContext();
  }

  /**
   * Returns the default persistent fetch context supplied by the wrapped daemon core.
   *
   * <p>Factories typically adjust the returned context immediately for one request, but the
   * baseline always comes from the live core so persistent GET defaults remain unchanged.
   *
   * @return default persistent fetch context template from the daemon core
   */
  @Override
  public FetchContext defaultPersistentFetchContext() {
    return core.getClientContext().getDefaultPersistentFetchContext();
  }

  /**
   * Returns the transfer-access policy owned by the surrounding FCP server runtime.
   *
   * <p>This intentionally does not read from {@code core.getRuntimePorts()}. Persistent global GET
   * request planning must stay aligned with the server runtime that supplied the download policy
   * and default directories.
   *
   * @return transfer policy used for DDA checks and default download resolution
   */
  @Override
  public TransferAccessPort transferAccess() {
    return transferAccess;
  }

  /**
   * Allocates a Binary Blob bucket through the wrapped daemon core.
   *
   * <p>The bucket comes from the core's bucket factory for the requested persistence class. This
   * keeps Binary Blob storage behavior identical to the pre-refactor GET path while exposing only a
   * narrow package-local seam to callers.
   *
   * @param maxOutputLength maximum number of bytes the bucket should be prepared to hold
   * @param persistentForever whether the forever-persistent bucket factory should be used
   * @return newly allocated bucket suitable for Binary Blob output
   * @throws IOException if the underlying bucket factory cannot create the bucket
   */
  @Override
  public Bucket allocateBinaryBlobBucket(long maxOutputLength, boolean persistentForever)
      throws IOException {
    return core.getClientContext().getBucketFactory(persistentForever).makeBucket(maxOutputLength);
  }
}

package network.crypta.clients.fcp.bridge;

import java.io.DataInputStream;
import java.io.IOException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.persistence.PersistentRequestHandle;
import network.crypta.client.async.persistence.PersistentRequestIdentifier;
import network.crypta.client.async.persistence.PersistentRequestRecoveryCodec;
import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import network.crypta.clients.fcp.ClientRequest;
import network.crypta.clients.fcp.RequestIdentifier;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;

/**
 * Bridge adapter that restarts FCP persistent requests through the client-owned seam.
 *
 * <p>This codec bridges the client-owned recovery contract back to the existing FCP restart path.
 * It converts the client-owned durable identifier into the legacy FCP identifier type, narrows the
 * runtime-context seam back to {@link ClientContext} at the bridge boundary, and then delegates
 * reconstruction to {@link ClientRequest#restartFrom(DataInputStream, RequestIdentifier,
 * network.crypta.clients.fcp.FcpFetchRuntimeSupport, ClientContext, ChecksumChecker)}. The adapter
 * stays stateless, so startup wiring can reuse a single instance without coordinating additional
 * caches or configuration.
 */
public final class FcpPersistentRequestRecoveryCodec implements PersistentRequestRecoveryCodec {

  /**
   * Creates a stateless adapter for FCP compact-recovery records.
   *
   * <p>The adapter carries no mutable state and is safe to reuse for repeated startup and recovery
   * attempts.
   */
  public FcpPersistentRequestRecoveryCodec() {
    // Explicit for Javadoc coverage of the public API; the adapter is intentionally stateless.
  }

  /** {@inheritDoc} */
  @Override
  public PersistentRequestHandle restartFrom(
      DataInputStream dis,
      PersistentRequestIdentifier identifier,
      PersistentRequestRuntimeContext context,
      ChecksumChecker checker)
      throws StorageFormatException, IOException, ResumeFailedException {
    RequestIdentifier requestIdentifier =
        RequestIdentifier.fromPersistentRequestIdentifier(identifier);
    ClientContext clientContext = requireClientContext(context);
    return ClientRequest.restartFrom(
        dis,
        requestIdentifier,
        new CoreFcpFetchRuntimeSupport(
            clientContext,
            () -> {
              throw new UnsupportedOperationException(
                  "transferAccess is unavailable during persistent request recovery");
            }),
        clientContext,
        checker);
  }

  private static ClientContext requireClientContext(PersistentRequestRuntimeContext context) {
    if (context instanceof ClientContext clientContext) {
      return clientContext;
    }
    String contextType = context == null ? "null" : context.getClass().getName();
    throw new IllegalArgumentException(
        "FCP persistent request recovery requires ClientContext but got " + contextType);
  }
}

package network.crypta.clients.fcp.bridge;

import java.io.DataInputStream;
import java.io.IOException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.persistence.PersistentRequestHandle;
import network.crypta.client.async.persistence.PersistentRequestIdentifier;
import network.crypta.client.async.persistence.PersistentRequestRecoveryCodec;
import network.crypta.clients.fcp.ClientRequest;
import network.crypta.clients.fcp.RequestIdentifier;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;

/**
 * Bridge adapter that restarts FCP persistent requests through the client-owned seam.
 *
 * <p>This codec bridges the client-owned recovery contract back to the existing FCP restart path.
 * It converts the client-owned durable identifier into the legacy FCP identifier type and then
 * delegates reconstruction to {@link ClientRequest#restartFrom(DataInputStream, RequestIdentifier,
 * ClientContext, ChecksumChecker)}. The adapter stays stateless, so startup wiring can reuse a
 * single instance without coordinating additional caches or configuration.
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
      ClientContext context,
      ChecksumChecker checker)
      throws StorageFormatException, IOException, ResumeFailedException {
    RequestIdentifier requestIdentifier =
        RequestIdentifier.fromPersistentRequestIdentifier(identifier);
    return ClientRequest.restartFrom(dis, requestIdentifier, context, checker);
  }
}

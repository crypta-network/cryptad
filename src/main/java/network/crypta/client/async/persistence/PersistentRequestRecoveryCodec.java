package network.crypta.client.async.persistence;

import java.io.DataInputStream;
import java.io.IOException;
import network.crypta.client.async.ClientContext;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;

/**
 * Restarts durable requests from compact recovery records.
 *
 * <p>The recovery codec isolates endpoint-specific restart logic from the client-layer persistence
 * flow. {@code ClientLayerPersister} owns the framing, checksum handling, duplicate detection, and
 * overall fallback policy, while implementations of this interface know how to turn a compact
 * request-specific payload back into a live durable request for a particular runtime endpoint.
 *
 * <p>Keeping this seam separate from {@link PersistentRequestHandle} lets the client layer remain
 * stable while runtime adapters evolve independently. A codec may return {@code null} when a
 * particular durable request type cannot be restarted from compact data and should instead be
 * treated as unrecoverable.
 */
public interface PersistentRequestRecoveryCodec {

  /**
   * Restarts a request from a compact recovery-data stream.
   *
   * <p>The supplied stream contains only the request-specific payload inside the outer persistence
   * framing. Implementations may validate that payload against the durable identifier, reconstruct
   * the endpoint-owned request state, and attach the result to the live runtime context. They
   * should not consume bytes beyond the current request record.
   *
   * @param dis input positioned at the start of the request-specific compact recovery payload
   * @param identifier durable request identifier describing the request to recover
   * @param context live client runtime context that will own the restarted request
   * @param checker checksum helper available for request-specific restart logic when needed
   * @return recovered request, or {@code null} when this codec cannot restart the request type
   * @throws StorageFormatException if the compact recovery payload is malformed or inconsistent
   * @throws IOException if the recovery payload cannot be read from the stream
   * @throws ResumeFailedException if restart cannot attach the recovered request to the runtime
   */
  PersistentRequestHandle restartFrom(
      DataInputStream dis,
      PersistentRequestIdentifier identifier,
      ClientContext context,
      ChecksumChecker checker)
      throws StorageFormatException, IOException, ResumeFailedException;
}

package network.crypta.clients.fcp;

import java.util.Objects;

/**
 * Builds the replayable {@link PersistentPut} tag for a {@link ClientPut}.
 *
 * <p>{@link ClientPut} still owns the mutable insert lifecycle, the bridge-owned live execution,
 * and the Java-serialization hooks that preserve older persistent-request formats. This helper
 * isolates just the FCP-facing tag assembly step so the request class does not also need to know
 * how the stable {@code PersistentPut} wire payload is reconstructed. Callers typically use it when
 * replaying a running request to a reconnecting client or when re-emitting the persistent tag
 * before cached progress and completion messages.
 *
 * <p>The builder is deliberately shallow and read-only. It samples the request's current detached
 * request parameters, upload descriptor, insert-tuning metadata, and best-known data size, then
 * packages those values into a fresh {@link PersistentPut}. It never mutates the request, caches
 * state, or retains derived objects between calls, so repeated invocations simply reflect the
 * request snapshot visible at that moment.
 *
 * <p>The field mapping intentionally mirrors the historical in-request construction logic. That
 * keeps the FCP wire representation stable while letting the larger request class shed one cohesive
 * responsibility and a few type-level dependencies.
 *
 * <ul>
 *   <li>Reads detached request metadata from the current {@link ClientPut} snapshot.
 *   <li>Preserves the established {@link PersistentPut} field layout and semantics.
 *   <li>Produces a new message instance for each call so callers can queue or mutate it safely.
 * </ul>
 *
 * @see ClientPut
 * @see PersistentPut
 */
final class ClientPutPersistentTagBuilder {
  /** Request whose persistent insert state is being rendered into a tag message. */
  private final ClientPut request;

  /**
   * Creates a builder bound to one insert request snapshot source.
   *
   * <p>The builder stores only the owning request reference and derives all message content lazily
   * when {@link #persistentTagMessage()} runs. It does not capture a frozen snapshot at
   * construction time, so callers should create the builder near the point where they need the
   * resulting tag.
   *
   * @param request request whose current persistent-tag state should be rendered into a {@link
   *     PersistentPut} message
   */
  ClientPutPersistentTagBuilder(ClientPut request) {
    this.request = Objects.requireNonNull(request, "request");
  }

  /**
   * Builds the current persistent tag message for the request.
   *
   * <p>The returned {@link PersistentPut} preserves the existing FCP tag layout. It carries the
   * detached request parameters exposed to clients, the current upload descriptor, the insert
   * tuning values held in {@link ClientPutBase#ctx}, and the best-known data size for the payload.
   * The message is assembled from the request's current fields, so callers can use it for replay
   * and status publication without manually duplicating the mapping logic in multiple places.
   *
   * @return fresh {@link PersistentPut} message suitable for queue replay, reconnect handling, or
   *     other status publication paths that need the persistent insert tag
   */
  FCPMessage persistentTagMessage() {
    PersistentPutRequestMetadata metadata =
        new PersistentPutRequestMetadata(
            request.uri,
            request.started,
            request.ctx.getMaxInsertRetries(),
            request.ctx.getCompatibilityMode(),
            request.ctx.isDontCompress(),
            request.ctx.getCompressorDescriptor(),
            request.splitfileCryptoKeyForPersistentTag());
    return new PersistentPut(
        request.currentRequestParams(),
        request.persistentUploadDescriptor(),
        metadata,
        request.getDataSize());
  }
}

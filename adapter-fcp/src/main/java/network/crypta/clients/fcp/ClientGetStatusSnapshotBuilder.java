package network.crypta.clients.fcp;

import java.util.Objects;
import network.crypta.client.FetchContext;

/**
 * Builds persistent tag and status snapshot messages for {@link ClientGet}.
 *
 * <p>This helper assembles the metadata required for persistent request tags without exposing the
 * formatting details to the request itself. It gathers identifiers, scheduling flags, return-type
 * metadata, and fetch-context limits, then packages them into a {@link PersistentGet} message. The
 * resulting message is suitable for queueing on persistent clients and for replay to reconnecting
 * listeners.
 *
 * <p>The builder is intentionally small and stateless beyond the request reference. It relies on
 * the request for synchronization and assumes its callers have already established the desired
 * state. Because it only reads state and does not mutate it, the builder can be reused safely for
 * multiple tag emissions on the same request.
 *
 * <ul>
 *   <li><strong>Message composition</strong>: assembles {@link ClientRequestParams} and {@link
 *       PersistentGetDescriptor} into a {@link PersistentGet}.
 *   <li><strong>Persistence fidelity</strong>: preserves return type and size limits verbatim.
 * </ul>
 *
 * @see ClientGet
 */
final class ClientGetStatusSnapshotBuilder {
  /** The owning request whose cached metadata is rendered into persistent tags. */
  private final ClientGet request;

  /**
   * Creates a snapshot builder for a single request.
   *
   * <p>The builder stores only a reference to the request and expects the request to remain valid
   * for the lifetime of the builder. Callers should create one builder per request and avoid
   * sharing instances between unrelated requests.
   *
   * @param request request whose fields are sampled for persistent tag creation.
   */
  ClientGetStatusSnapshotBuilder(ClientGet request) {
    this.request = Objects.requireNonNull(request, "request");
  }

  /**
   * Builds the persistent tag message for the current request state.
   *
   * <p>The message captures identity, persistence settings, scheduling flags, and return-type
   * metadata so that persistent queues can restore the request after restarts. The returned message
   * is a fresh instance and can be queued or replayed without mutating the builder or request.
   *
   * @return {@link PersistentGet} message describing the request's current persistent metadata.
   */
  FCPMessage persistentTagMessage() {
    ClientRequestParams requestParams =
        new ClientRequestParams(
            request.uri,
            request.identifier,
            request.verbosity,
            request.priorityClass,
            request.persistence,
            request.isRealTime(),
            request.clientToken,
            request.client.isGlobalQueue);
    FetchContext fetchContext = request.fetchContextForGetter();
    PersistentGetDescriptor descriptor =
        new PersistentGetDescriptor(
            request.returnTypeForReplay(),
            request.targetFileForLifecycle(),
            request.started,
            fetchContext.getMaxNonSplitfileRetries(),
            request.binaryBlobRequested(),
            fetchContext.getMaxOutputLength());
    return new PersistentGet(requestParams, descriptor);
  }
}

package network.crypta.clients.fcp;

import java.util.Objects;
import network.crypta.support.api.Bucket;

/**
 * Replays or dispatches FCP messages for {@link ClientGet} instances.
 *
 * <p>This helper is responsible for turning cached request state into outbound protocol messages
 * when a client reconnects or when queued updates must be delivered. It keeps message sequencing
 * and replay logic separate from the request lifecycle so that {@link ClientGet} can focus on state
 * transitions, persistence, and retry policy. Typical call sites construct one helper per request
 * and delegate message emission from queueing or resume flows.
 *
 * <p>The helper does not retain a mutable state beyond the reference to its request. It
 * synchronizes with the request when reading composite state, and it never mutates the request
 * directly. All methods are designed to be idempotent with respect to message replay; they emit
 * messages based on the current cached snapshot only.
 *
 * <ul>
 *   <li><strong>Replay sequencing</strong>: emits tags, progress, metadata, and completion
 *       messages.
 *   <li><strong>Delivery routing</strong>: chooses the correct destination based on persistence.
 *   <li><strong>Payload handling</strong>: assembles {@link AllDataMessage} when applicable.
 * </ul>
 *
 * @see ClientGet
 */
final class ClientGetMessageReplay {
  /** Owning request whose cached state is replayed to FCP clients. */
  private final ClientGet request;

  /**
   * Creates a replay helper bound to a single request instance.
   *
   * <p>The helper keeps only a reference to the request and relies on the request's own
   * synchronization for consistent snapshots. Callers should create a new helper for each request
   * and avoid sharing instances between requests.
   *
   * @param request owning request providing cached message state; must be non-null.
   */
  ClientGetMessageReplay(ClientGet request) {
    this.request = Objects.requireNonNull(request, "request");
  }

  /**
   * Sends cached state to a reconnecting client.
   *
   * <p>The method emits persistent tags, progress messages, compatibility metadata, and optional
   * payloads in the same sequence used for live updates. When {@code onlyData} is true, the method
   * enforces {@link ClientGet.ReturnType#DIRECT} and otherwise emits a protocol error. The method
   * is idempotent and uses only cached request state; it does not trigger additional network
   * activity or alter the underlying request.
   *
   * @param handler output handler used to enqueue messages to the destination connection.
   * @param listRequestIdentifier optional identifier added to replayed messages; may be null.
   * @param includeData {@code true} to include {@link AllDataMessage} bodies when present.
   * @param onlyData {@code true} to suppress metadata and send only payload frames.
   */
  void sendPendingMessages(
      FCPConnectionOutputHandler handler,
      String listRequestIdentifier,
      boolean includeData,
      boolean onlyData) {
    if (!onlyData) {
      FCPMessage msg = request.persistentTagMessage();
      handler.handler.send(FCPMessage.withListRequestIdentifier(msg, listRequestIdentifier));
      SimpleProgressMessage progress = request.state().getProgressPending();
      if (progress != null) {
        handler.handler.send(FCPMessage.withListRequestIdentifier(progress, listRequestIdentifier));
      }
      if (request.state().hasSentToNetwork()) {
        handler.handler.send(
            FCPMessage.withListRequestIdentifier(
                new SendingToNetworkMessage(request.identifier, request.global),
                listRequestIdentifier));
      }
      if (request.finished) {
        request.trySendDataFoundOrGetFailed(handler, listRequestIdentifier);
      }
    } else if (request.returnTypeForReplay() != ClientGet.ReturnType.DIRECT) {
      FCPMessage msg =
          new ProtocolErrorMessage(
              ProtocolErrorMessage.WRONG_RETURN_TYPE,
              false,
              "No AllData",
              request.identifier,
              request.global);
      handler.handler.send(msg);
      return;
    }

    if (includeData) {
      request.trySendAllDataMessage(handler, listRequestIdentifier);
    }

    CompatibilityMode cmsg;
    ExpectedHashes hashesMessage;
    ExpectedMIME mimeMsg = null;
    ExpectedDataLength lengthMsg = null;
    synchronized (request.persistenceLock()) {
      ClientGetState state = request.state();
      cmsg =
          new CompatibilityMode(
              request.identifier, request.global, state.getCompatibilityAnalyser());
      hashesMessage = state.getExpectedHashes();
      if (state.getFoundDataMimeType() != null) {
        mimeMsg =
            new ExpectedMIME(request.identifier, request.global, state.getFoundDataMimeType());
      }
      if (state.getFoundDataLength() > 0) {
        lengthMsg =
            new ExpectedDataLength(request.identifier, request.global, state.getFoundDataLength());
      }
    }
    handler.handler.send(FCPMessage.withListRequestIdentifier(cmsg, listRequestIdentifier));

    if (hashesMessage != null) {
      handler.handler.send(
          FCPMessage.withListRequestIdentifier(hashesMessage, listRequestIdentifier));
    }

    if (mimeMsg != null) {
      handler.handler.send(FCPMessage.withListRequestIdentifier(mimeMsg, listRequestIdentifier));
    }
    if (lengthMsg != null) {
      handler.handler.send(FCPMessage.withListRequestIdentifier(lengthMsg, listRequestIdentifier));
    }
  }

  /**
   * Queues a progress message using the appropriate connection or persistent queue.
   *
   * <p>Connection-scoped requests send directly to the original handler when available. Persistent
   * requests queue the message on the owning {@link PersistentRequestClient} so that reconnections
   * and watchers receive consistent updates.
   *
   * @param msg progress message to deliver; must already be fully constructed.
   * @param verbosityMask verbosity bitmask used when queueing to persistent clients.
   */
  void queueProgressMessageInner(FCPMessage msg, int verbosityMask) {
    if (request.persistence == ClientRequest.Persistence.CONNECTION) {
      if (request.origHandler != null) {
        request.origHandler.send(msg);
      }
      return;
    }
    request.client.queueClientRequestMessage(msg, verbosityMask);
  }

  /**
   * Emits a terminal {@link DataFoundMessage} or {@link GetFailedMessage} based on cached state.
   *
   * <p>The method chooses the correct destination based on persistence and whether a handler was
   * supplied. When a success is recorded, it mirrors {@link AllDataMessage} timing so clients
   * receive consistent timestamps even if completion time was recorded later in the lifecycle.
   *
   * @param handler optional handler to target directly; may be null to use queue routing.
   * @param listRequestIdentifier optional list identifier to attach to outgoing messages.
   */
  void trySendDataFoundOrGetFailed(
      FCPConnectionOutputHandler handler, String listRequestIdentifier) {
    FCPMessage msg;

    // Don't need to lock. succeeded is only ever set, never unset.
    // and succeeded and getFailedMessage are both atomic.
    if (request.state().hasSucceeded()) {
      // Mirrors AllDataMessage so connection-scoped clients receive DataFound with consistent
      // timestamps even if completionTime was not set by finish().
      msg =
          new DataFoundMessage(
              request.state().getFoundDataLength(),
              request.state().getFoundDataMimeType(),
              request.identifier,
              request.global,
              request.startupTime,
              request.completionTime != 0 ? request.completionTime : System.currentTimeMillis());
    } else {
      msg = request.state().getFailedMessage();
    }

    if (handler == null && request.persistence == ClientRequest.Persistence.CONNECTION) {
      if (request.origHandler != null) {
        request.origHandler.send(FCPMessage.withListRequestIdentifier(msg, listRequestIdentifier));
      }
    } else if (handler != null) {
      handler.handler.send(FCPMessage.withListRequestIdentifier(msg, listRequestIdentifier));
    } else {
      request.client.queueClientRequestMessage(
          FCPMessage.withListRequestIdentifier(msg, listRequestIdentifier), 0);
    }
  }

  /**
   * Emits an {@link AllDataMessage} payload when available.
   *
   * <p>For connection-scoped requests without an explicit handler, the message is sent to the
   * original handler. For other cases, it is sent through the provided handler. When the request is
   * not in {@link ClientGet.ReturnType#DIRECT} mode, this method is a no-op.
   *
   * @param handler handler to send through when non-null; may be null for connection replay.
   * @param listRequestIdentifier optional list identifier added to the outgoing message.
   */
  void trySendAllDataMessage(FCPConnectionOutputHandler handler, String listRequestIdentifier) {
    if (request.persistence == ClientRequest.Persistence.CONNECTION && handler == null) {
      if (request.origHandler != null) {
        FCPMessage allData =
            FCPMessage.withListRequestIdentifier(getAllDataMessage(), listRequestIdentifier);
        if (allData != null) {
          request.origHandler.send(allData);
        }
      }
      return;
    }
    if (handler != null) {
      FCPMessage allData =
          FCPMessage.withListRequestIdentifier(getAllDataMessage(), listRequestIdentifier);
      if (allData != null) {
        handler.handler.send(allData);
      }
    }
  }

  /**
   * Builds an {@link AllDataMessage} snapshot when direct delivery is enabled.
   *
   * <p>The method reads cached bucket, MIME type, and completion time under synchronization and
   * returns {@code null} when the request is not configured for direct delivery. For connection
   * scope, it marks the message for freeing after sending.
   *
   * @return a new {@link AllDataMessage} snapshot, or {@code null} when unavailable.
   */
  private AllDataMessage getAllDataMessage() {
    if (request.returnTypeForReplay() != ClientGet.ReturnType.DIRECT) {
      return null;
    }
    Bucket bucket;
    String mimeType;
    long completionTime;
    synchronized (request.persistenceLock()) {
      ClientGetState state = request.state();
      bucket = state.getReturnBucketDirect();
      mimeType = state.getFoundDataMimeType();
      completionTime = request.completionTime;
    }
    AllDataMessage msg =
        new AllDataMessage(
            bucket,
            request.identifier,
            request.global,
            request.startupTime,
            completionTime,
            mimeType);
    if (request.persistence == ClientRequest.Persistence.CONNECTION) {
      msg.setFreeOnSent();
    }
    return msg;
  }
}

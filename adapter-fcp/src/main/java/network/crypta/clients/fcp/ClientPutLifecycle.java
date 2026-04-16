package network.crypta.clients.fcp;

import network.crypta.client.InsertException;
import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Applies request-lifecycle bookkeeping for a single {@link ClientPut}.
 *
 * <p>{@link ClientPut} still owns the mutable insert state, Java-serialization hooks, and
 * user-visible accessors. This helper isolates the queue-oriented lifecycle transitions that
 * surround the live insert execution: registration, start, restart, compression-state cache
 * updates, and final removal from persistent queues. Keeping those transitions together trims the
 * request class without changing the observable behavior of FCP inserts.
 *
 * <p>The helper is request-bound and intentionally state-free beyond the request reference. Callers
 * create one helper per request and delegate lifecycle entry points to it; the helper in turn
 * mutates only the owning request and its related caches.
 */
final class ClientPutLifecycle {
  /** Logger used for low-volume lifecycle diagnostics around start and restart transitions. */
  private static final Logger LOG = LoggerFactory.getLogger(ClientPutLifecycle.class);

  /** Request whose mutable state and caches are updated by this helper. */
  private final ClientPut request;

  /**
   * Creates a lifecycle helper bound to one request instance.
   *
   * @param request request whose queue-facing lifecycle transitions should be coordinated
   */
  ClientPutLifecycle(ClientPut request) {
    this.request = request;
  }

  /**
   * Registers the request with its persistent owner and optionally queues the first persistent tag.
   *
   * <p>Connection-scoped inserts are already owned by the live socket and therefore skip
   * persistent-client registration. Reboot and forever requests must be registered immediately so
   * the owner can track identifier uniqueness and replay messages to reconnecting clients.
   *
   * @param noTags {@code true} to suppress the initial persistent-tag message after registration
   * @throws IdentifierCollisionException if the persistent owner already tracks the identifier
   */
  void register(boolean noTags) throws IdentifierCollisionException {
    if (request.persistence != ClientRequest.Persistence.CONNECTION) {
      request.client.register(request);
    }
    if (request.persistence != ClientRequest.Persistence.CONNECTION && !noTags) {
      FCPMessage msg = request.persistentTagMessage();
      request.client.queueClientRequestMessage(msg, 0);
    }
  }

  /**
   * Starts the live insert execution and synchronizes queue-side bookkeeping around that start.
   *
   * <p>The helper preserves the existing request behavior: terminal requests are ignored, the live
   * execution is started exactly once per entry, persistent requests may queue a tag message, and
   * the started flag and request-status cache are updated on both success and failure paths. Any
   * synchronous start failure is normalized through {@link ClientPut#onFailure(InsertException,
   * FcpInsertCallbackState)} so client-visible error reporting does not change.
   *
   * @param context detached runtime context passed through to the live execution start path
   */
  void start(PersistentRequestRuntimeContext context) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Starting {} : {}", request, request.identifier);
    }
    synchronized (request) {
      if (request.finished) {
        return;
      }
    }
    try {
      request.putter.start(context);
      synchronized (request) {
        if (request.persistence != ClientRequest.Persistence.CONNECTION && !request.finished) {
          FCPMessage msg = request.persistentTagMessage();
          request.client.queueClientRequestMessage(msg, 0);
        }
        request.started = true;
      }
      RequestStatusCache cache = requestStatusCache();
      if (cache != null) {
        cache.updateStarted(request.identifier, true);
      }
    } catch (InsertException e) {
      synchronized (request) {
        request.started = true;
      }
      request.onFailure(e, (FcpInsertCallbackState) null);
    } catch (Exception t) {
      synchronized (request) {
        request.started = true;
      }
      request.onFailure(
          new InsertException(InsertException.InsertExceptionMode.INTERNAL_ERROR, t, null),
          (FcpInsertCallbackState) null);
    }
  }

  /**
   * Restarts a finished insert attempt when the underlying execution still supports restart.
   *
   * <p>The helper first resets the request-owned restart state, then updates the status cache to
   * show a stop/start transition around the restart call. A successful restart clears the generated
   * URI and marks the request as started again. Insert failures are reported through the existing
   * failure path, so persistent queues and clients observe the same behavior as before the helper
   * extraction.
   *
   * @param context detached runtime context passed through to the live execution restart path
   * @return {@code true} when the restart path was accepted and executed without synchronous
   *     failure; otherwise {@code false}
   */
  boolean restart(PersistentRequestRuntimeContext context) {
    if (!request.canRestart()) {
      return false;
    }
    setVarsRestart();
    try {
      RequestStatusCache cache = requestStatusCache();
      if (cache != null) {
        cache.updateStarted(request.identifier, false);
      }
      if (request.putter.restart(context)) {
        synchronized (request) {
          request.generatedURI = null;
          request.started = true;
        }
      }
      if (cache != null) {
        cache.updateStarted(request.identifier, true);
      }
      return true;
    } catch (InsertException e) {
      request.onFailure(e, (FcpInsertCallbackState) null);
      return false;
    }
  }

  /**
   * Resets request-owned restart state and refreshes compression status in the request cache.
   *
   * <p>This keeps the cache aligned with the request's internal compression state before a restart
   * attempt is made, even if the later restart fails synchronously.
   */
  void setVarsRestart() {
    request.resetBaseVarsForRestart();
    RequestStatusCache cache = requestStatusCache();
    if (cache != null) {
      cache.updateCompressionStatus(request.identifier, request.isCompressing());
    }
  }

  /**
   * Applies final request cleanup when the request is removed from persistent ownership.
   *
   * <p>Forever-persistent requests drop their live putter reference because that execution is not
   * meaningful once the durable request has been removed. The helper then delegates to the base
   * removal hook, so common insert cleanup still runs.
   *
   * @param context detached runtime context supplied by the removal path
   */
  void requestWasRemoved(PersistentRequestRuntimeContext context) {
    if (request.persistence == ClientRequest.Persistence.FOREVER) {
      request.putter = null;
    }
    request.requestWasRemovedBase(context);
  }

  /**
   * Records that compression work has started and mirrors that state into the request cache.
   *
   * <p>The update is idempotent. If the request already recorded a terminal compression state, this
   * method returns without emitting another cache update.
   */
  void onStartCompressing() {
    if (!request.markCompressionStarted()) {
      return;
    }
    RequestStatusCache cache = requestStatusCache();
    if (cache != null) {
      cache.updateCompressionStatus(request.identifier, ClientPut.COMPRESS_STATE.COMPRESSING);
    }
  }

  /**
   * Records that compression work has completed and mirrors that state into the request cache.
   *
   * <p>The helper only emits the cache transition once, even if multiple completion signals arrive
   * because of legacy callback ordering.
   */
  void onStopCompressing() {
    if (!request.markCompressionFinished()) {
      return;
    }
    RequestStatusCache cache = requestStatusCache();
    if (cache != null) {
      cache.updateCompressionStatus(request.identifier, ClientPut.COMPRESS_STATE.WORKING);
    }
  }

  /**
   * Returns the request-status cache associated with the current persistent client, if any.
   *
   * @return request-status cache for this request's owner, or {@code null} when the request is not
   *     currently attached to a persistent client
   */
  private RequestStatusCache requestStatusCache() {
    return request.client == null ? null : request.client.getRequestStatusCache();
  }
}

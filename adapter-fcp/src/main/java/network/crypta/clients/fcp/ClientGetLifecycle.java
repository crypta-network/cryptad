package network.crypta.clients.fcp;

import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ResumeFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Applies lifecycle transitions for {@link ClientGet} without exposing additional API surface.
 *
 * <p>This helper centralizes success, failure, migration, and removal paths so that the surrounding
 * request stays focused on message wiring and persistence. It mutates the owning request under
 * synchronization, updates cached fields such as MIME type, payload length, and completion time,
 * and then triggers the appropriate outbound notifications. Callers generally construct this helper
 * once per request and delegate lifecycle events as they occur.
 *
 * <p>Thread-safety is inherited from the request: most state transitions are synchronized on the
 * {@code ClientGet} instance, and the helper never retains mutable state of its own. It is
 * intentionally not reusable across requests and assumes it will only be invoked by the owning
 * request instance.
 *
 * <ul>
 *   <li><strong>Success handling</strong>: captures result metadata and notifies clients.
 *   <li><strong>Failure handling</strong>: records failure context and triggers cleanup.
 *   <li><strong>Removal</strong>: synthesizes cancellation and releases retained buckets.
 * </ul>
 *
 * @see ClientGet
 */
final class ClientGetLifecycle {
  /** Logger used for lifecycle diagnostics and duplicate-callback guards. */
  private static final Logger LOG = LoggerFactory.getLogger(ClientGetLifecycle.class);

  /** The owning request whose state is updated by lifecycle transitions. */
  private final ClientGet request;

  /**
   * Creates a lifecycle helper bound to a single request.
   *
   * <p>The helper keeps only a reference to the request and relies on the request's own locking
   * discipline for thread safety. Callers should create one helper per request and avoid sharing it
   * across instances.
   *
   * @param request request whose state transitions are managed by this helper.
   */
  ClientGetLifecycle(ClientGet request) {
    this.request = request;
  }

  /**
   * Records a successful completion and emits completion messages.
   *
   * <p>The method snapshots MIME type, payload length, and completion time, stores the payload
   * bucket when {@link ClientGet.ReturnType#DIRECT} applies, and then forwards completion events to
   * interested clients. Duplicate invocations are ignored to preserve idempotency. For BinaryBlob
   * requests, the payload length and MIME type are derived from the blob bucket.
   *
   * @param result result wrapper providing MIME metadata and the decoded data bucket.
   * @param state execution handle used to access Binary Blob buckets when required.
   */
  void onSuccess(FetchResult result, ClientGetExecution state) {
    LOG.debug("Succeeded: {}", request.identifier);
    ClientGetRequestProfile requestProfile = request.requestProfile();
    Bucket data = requestProfile.binaryBlob() ? state.blobBucket() : result.asBucket();
    ClientGetState requestState = request.state();
    synchronized (request.persistenceLock()) {
      if (requestState.hasSucceeded()) {
        LOG.error("onSuccess called twice for {} ({})", request, request.identifier);
        return; // We might be called twice; ignore it if so.
      }
      request.started = true;
      if (!requestProfile.binaryBlob()) {
        requestState.setFoundDataMimeType(result.getMimeType());
      } else {
        requestState.setFoundDataMimeType(ClientGetGetterFactory.binaryBlobMimeType());
      }

      // completionTime is set here rather than in finish() for two reasons:
      // 1. It must be set inside the lock.
      // 2. It must be set before AllData is sent so it is consistent.
      request.completionTime = System.currentTimeMillis();
      requestState.setProgressPending(null);
      requestState.setFoundDataLength(data.size());
      requestState.setSucceeded(true);
      request.finished = true;
      if (requestProfile.returnType() == ClientGet.ReturnType.DIRECT) {
        requestState.setReturnBucketDirect(data);
      }
    }
    request.trySendDataFoundOrGetFailed(null, null);
    request.trySendAllDataMessage(null, null);
    request.finish();
    if (request.client != null) {
      request.client.notifySuccess(request);
    }
  }

  /**
   * Forces a successful state during migration validation.
   *
   * <p>This method is intended for controlled migration flows that replay the persisted state. It
   * validates that disk or direct bucket outputs match the recorded length, stores the bucket when
   * appropriate, and records the provided completion timestamp. Any mismatch results in a {@link
   * ResumeFailedException} to signal that the request should restart instead of trusting corrupted
   * state.
   *
   * @param completionTime epoch milliseconds to record as the completion timestamp.
   * @param data bucket holding the payload when {@link ClientGet.ReturnType#DIRECT} applies.
   * @throws ResumeFailedException when stored output does not match the recorded metadata.
   */
  void setSuccessForMigration(long completionTime, Bucket data) throws ResumeFailedException {
    ClientGetState requestState = request.state();
    synchronized (request.persistenceLock()) {
      requestState.setSucceeded(true);
      request.started = true;
      request.finished = true;
      request.completionTime = completionTime;
      ClientGetRequestProfile requestProfile = request.requestProfile();
      ClientGet.ReturnType returnType = requestProfile.returnType();
      if (returnType == null) {
        throw new ResumeFailedException("Success but return type is missing");
      }
      java.io.File targetFile = requestProfile.targetFile();
      switch (returnType) {
        case ClientGet.ReturnType type when type == ClientGet.ReturnType.NONE -> {
          // Nothing to validate.
        }
        case ClientGet.ReturnType type
            when type == ClientGet.ReturnType.DISK
                && (targetFile == null
                    || !targetFile.exists()
                    || targetFile.length() != requestState.getFoundDataLength()) ->
            throw new ResumeFailedException("Success but target file doesn't exist or isn't valid");
        case ClientGet.ReturnType type when type == ClientGet.ReturnType.DISK -> {
          // Validation already passed.
        }
        case ClientGet.ReturnType type
            when type == ClientGet.ReturnType.DIRECT
                && data.size() != requestState.getFoundDataLength() -> {
          requestState.setReturnBucketDirect(data);
          throw new ResumeFailedException(
              "Success but temporary data bucket doesn't exist or isn't valid");
        }
        case ClientGet.ReturnType type when type == ClientGet.ReturnType.DIRECT ->
            requestState.setReturnBucketDirect(data);
        case ClientGet.ReturnType type when type == ClientGet.ReturnType.CHUNKED ->
            throw new ResumeFailedException("Chunked return type not supported for migration");
        default -> throw new IllegalStateException("Unexpected return type: " + returnType);
      }
    }
  }

  /**
   * Records a failure outcome and notifies listeners.
   *
   * <p>The method caches expected size and MIME hints from the exception, constructs the failure
   * message, and marks the request as finished so restart logic can take over. If the request was
   * already finished, it returns immediately without side effects. The request's payload buckets
   * are intentionally preserved for potential restart attempts.
   *
   * @param e failure descriptor that supplies mode, size, and MIME hints.
   */
  void onFailure(FetchException e) {
    if (request.finished) {
      return;
    }
    ClientGetState requestState = request.state();
    synchronized (request.persistenceLock()) {
      if (e.getExpectedSize() != 0) {
        requestState.setFoundDataLength(e.getExpectedSize());
      }
      if (e.getExpectedMimeType() != null) {
        requestState.setFoundDataMimeType(e.getExpectedMimeType());
      }
      requestState.setSucceeded(false);
      requestState.setFailedMessage(new GetFailedMessage(e, request.identifier, request.global));
      request.finished = true;
      request.started = true;
      request.completionTime = System.currentTimeMillis();
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug("Caught {}", e, e);
    }
    request.trySendDataFoundOrGetFailed(null, null);
    // We do not want the data to be removed on failure, because the request
    // may be restarted, and the bucket persists on the getter, even if we get rid of it here.
    request.finish();
    if (request.client != null) {
      request.client.notifyFailure(request);
    }
  }

  /**
   * Handles removal of a request from its owning queue.
   *
   * <p>If the request is still running, this method synthesizes a cancellation failure so that
   * observers receive a terminal status. It then emits a removal notification to persistent clients
   * and frees any retained in-memory buckets. The method does not attempt to stop network activity;
   * it assumes the scheduler already detached the underlying fetcher.
   */
  void requestWasRemoved() {
    // if the request is still running, send a GetFailed with code=canceled
    if (!request.finished) {
      ClientGetState requestState = request.state();
      synchronized (request.persistenceLock()) {
        requestState.setSucceeded(false);
        request.finished = true;
        FetchException cancelled = new FetchException(FetchExceptionMode.CANCELLED);
        requestState.setFailedMessage(
            new GetFailedMessage(cancelled, request.identifier, request.global));
      }
      request.trySendDataFoundOrGetFailed(null, null);
    }
    // notify client that the request was removed
    FCPMessage msg = new PersistentRequestRemovedMessage(request.getIdentifier(), request.global);
    if (request.persistence != ClientRequest.Persistence.CONNECTION) {
      request.client.queueClientRequestMessage(msg, 0);
    }

    request.freeData();
  }
}

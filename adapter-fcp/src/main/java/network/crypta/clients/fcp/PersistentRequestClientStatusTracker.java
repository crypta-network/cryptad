package network.crypta.clients.fcp;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks status-cache state for a {@link PersistentRequestClient}.
 *
 * <p>This helper exists primarily to satisfy Sonar rule {@code java:S6539} ("Monster Class") by
 * separating status-cache translation and rebuild logic from the connection, replay, and watcher
 * coordination that remains on {@link PersistentRequestClient}. It owns the optional {@link
 * RequestStatusCache} used by global queues and translates live request outcomes into cached upload
 * and download status entries.
 *
 * <p>The class is deliberately package-private because it is an implementation detail of {@link
 * PersistentRequestClient}, not a reusable status service for the wider FCP adapter. It operates on
 * already-materialized {@link ClientRequest} instances, keeps the global-queue cache optional, and
 * preserves the existing request-status behavior for reboot and forever queues without changing
 * request persistence or replay semantics. Callers hand it requests at key lifecycle moments such
 * as register, finish, remove, and cache rebuild, and the helper converts those events into the
 * concrete cache mutations that UI and API status consumers already expect.
 *
 * <ul>
 *   <li>Owns the optional {@link RequestStatusCache} instance for global queues.
 *   <li>Translates live request outcomes into detached download and upload status snapshots.
 *   <li>Rebuilds cached status state from persistent requests after restart when needed.
 * </ul>
 */
final class PersistentRequestClientStatusTracker {
  /** Logger used for status-cache rebuild failures and other internal tracker diagnostics. */
  private static final Logger LOG =
      LoggerFactory.getLogger(PersistentRequestClientStatusTracker.class);

  /**
   * Optional cache exposed to global-queue status consumers.
   *
   * <p>The cache is present only for global queues because connection-local request clients do not
   * publish long-lived status snapshots through the same status APIs.
   */
  private final RequestStatusCache statusCache;

  /**
   * Creates a tracker for one persistent-request client.
   *
   * <p>Global clients receive a dedicated {@link RequestStatusCache}, while non-global clients keep
   * the field {@code null} and effectively turn the helper into a no-op for cache-specific work.
   * That mirrors the pre-refactor behavior without forcing callers to branch at every status update
   * site.
   *
   * @param globalQueue whether the owning persistent client contributes to the global status cache
   */
  PersistentRequestClientStatusTracker(boolean globalQueue) {
    statusCache = globalQueue ? new RequestStatusCache() : null;
  }

  /**
   * Adds a newly registered request to the in-memory status cache when one exists.
   *
   * <p>The method snapshots the request's current status object and indexes it under the correct
   * download or upload collection. Unknown request subtypes are intentionally ignored here because
   * only download and insert requests are expected to populate the FCP status cache.
   *
   * @param request newly registered request whose current status should be cached
   */
  void register(ClientRequest request) {
    if (statusCache == null) {
      return;
    }
    if (request instanceof ClientGet) {
      statusCache.addDownload((DownloadRequestStatus) request.getStatus());
    } else if (request instanceof ClientPutBase) {
      statusCache.addUpload((UploadRequestStatus) request.getStatus());
    }
  }

  /**
   * Applies terminal request state to the cache when the owning request finishes.
   *
   * <p>Downloads and uploads use different outcome payloads, so the method dispatches to
   * type-specific completion helpers rather than trying to update the cache through a uniform
   * object model. Any unexpected request subtype is treated as a programming error because it would
   * indicate that a non-cacheable request reached a cache-oriented lifecycle hook.
   *
   * @param request finished request whose terminal status should be reflected in the cache
   */
  void finishedClientRequest(ClientRequest request) {
    if (statusCache == null) {
      return;
    }
    switch (request) {
      case ClientGet download -> handleDownloadCompletion(download);
      case ClientPutBase upload -> handleUploadCompletion(upload);
      default -> throw new IllegalStateException("Unexpected request type: " + request.getClass());
    }
  }

  /**
   * Removes one cached status entry by request identifier when the owning request is deleted.
   *
   * @param identifier request identifier to evict from the in-memory status cache
   */
  void removeByIdentifier(String identifier) {
    if (statusCache != null) {
      statusCache.removeByIdentifier(identifier);
    }
  }

  /** Clears every cached status entry when the owning client drops all requests. */
  void clear() {
    if (statusCache != null) {
      statusCache.clear();
    }
  }

  /**
   * Appends all cached status entries to the supplied output list.
   *
   * <p>Callers use this to expose the current global status view without giving external code
   * direct write access to the cache instance itself.
   *
   * @param status destination list that receives the cached request statuses
   */
  void addPersistentRequestStatus(List<RequestStatus> status) {
    requireStatusCache().addTo(status);
  }

  /**
   * Finds the completed download request for the supplied key among unacknowledged completions.
   *
   * <p>The search stays intentionally simple because the completed list is already maintained by
   * the owning {@link PersistentRequestClient}. Only {@link ClientGet} instances are relevant here;
   * all other request types are skipped.
   *
   * @param completedUnackedRequests finished requests that still await client acknowledgement
   * @param key key whose completed download request should be returned
   * @return matching completed {@link ClientGet}, or {@code null} when none is present
   */
  ClientGet getCompletedRequest(List<ClientRequest> completedUnackedRequests, FreenetURI key) {
    for (ClientRequest request : completedUnackedRequests) {
      if (!(request instanceof ClientGet getter)) {
        continue;
      }
      if (getter.getURI().equals(key)) {
        return getter;
      }
    }
    return null;
  }

  /**
   * Returns the backing status cache if this tracker owns one.
   *
   * @return global status cache for the owning client, or {@code null} for non-global queues
   */
  RequestStatusCache getRequestStatusCache() {
    return statusCache;
  }

  /**
   * Rebuilds the status cache from a list of persistent requests loaded after restart.
   *
   * <p>The rebuild is best-effort: one broken request status should not prevent the remainder of
   * the cache from being reconstructed. Requests are first converted into detached {@link
   * RequestStatus} snapshots and then re-indexed as downloads or uploads to preserve the existing
   * cache layout.
   *
   * @param persistentRequests live persistent requests whose cached status state should be rebuilt
   */
  void updateRequestStatusCache(List<ClientRequest> persistentRequests) {
    RequestStatusCache cache = requireStatusCache();
    LOG.info("Loading cache of request statuses...");
    List<RequestStatus> statuses = new ArrayList<>();
    for (ClientRequest request : persistentRequests) {
      try {
        statuses.add(request.getStatus());
      } catch (Exception t) {
        LOG.error("BROKEN REQUEST LOADING PERSISTENT REQUEST STATUS: {}", t.getMessage(), t);
      }
    }
    for (RequestStatus status : statuses) {
      if (status instanceof DownloadRequestStatus requestStatus) {
        cache.addDownload(requestStatus);
      } else {
        cache.addUpload((UploadRequestStatus) status);
      }
    }
  }

  /**
   * Translates a finished upload request into the cached upload-status representation.
   *
   * <p>The helper extracts the final URI and any available failure details from the request's
   * {@link PutFailedMessage}, then forwards that terminal state into {@link RequestStatusCache}.
   *
   * @param upload finished upload request whose outcome should update the cache
   */
  private void handleUploadCompletion(ClientPutBase upload) {
    PutFailedMessage message = upload.getFailureMessage();
    InsertExceptionMode failureCode = null;
    String shortFailMessage = null;
    String longFailMessage = null;
    if (message != null) {
      failureCode = message.failureMode;
      shortFailMessage = message.getShortFailedMessage();
      longFailMessage = message.getLongFailedMessage();
    }
    statusCache.finishedUpload(
        upload.getIdentifier(),
        upload.hasSucceeded(),
        upload.getGeneratedURI(),
        failureCode,
        shortFailMessage,
        longFailMessage);
  }

  /**
   * Translates a finished download request into the cached download-status representation.
   *
   * <p>The helper captures failure details, MIME type, byte count, filter state, and a shadow copy
   * of the final bucket when one is available. That keeps the status cache detached from the live
   * request object while preserving the local-cache lookup behavior expected by higher layers.
   *
   * @param download finished download request whose outcome should update the cache
   */
  private void handleDownloadCompletion(ClientGet download) {
    GetFailedMessage failureMessage = download.state().getFailedMessage();
    FetchExceptionMode failureCode = null;
    String shortFailMessage = null;
    String longFailMessage = null;
    if (failureMessage != null) {
      failureCode = failureMessage.failureMode;
      shortFailMessage = failureMessage.getShortFailedMessage();
      longFailMessage = failureMessage.getLongFailedMessage();
    }
    Bucket shadow = download.getBucket();
    if (shadow != null) {
      shadow = shadow.createShadow();
    }
    DownloadOutcomeInfo outcome =
        new DownloadOutcomeInfo(
            download.getDataSize(),
            download.getMIMEType(),
            failureCode,
            shortFailMessage,
            longFailMessage,
            shadow,
            download.filterData());
    statusCache.finishedDownload(download.getIdentifier(), download.hasSucceeded(), outcome);
  }

  /**
   * Returns the backing cache or fails fast when the owning client has no global cache.
   *
   * @return non-null status cache owned by this tracker
   * @throws NullPointerException when called for a non-global queue without a status cache
   */
  private RequestStatusCache requireStatusCache() {
    return Objects.requireNonNull(statusCache, "statusCache");
  }
}

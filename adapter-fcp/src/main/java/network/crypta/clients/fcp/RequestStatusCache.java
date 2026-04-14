package network.crypta.clients.fcp;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.async.CacheFetchResult;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.clients.fcp.ClientPut.COMPRESS_STATE;
import network.crypta.keys.FreenetURI;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.NoFreeBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * In-memory cache tracking the lifecycle of client requests handled via FCP identifiers and URIs.
 *
 * <p>The cache keeps a primary index by request identifier and secondary indexes for download
 * requests (by {@link FreenetURI}) and uploads (by final URI). It is designed for callers that
 * routinely look up, update, and remove the request state while UI components render progress or
 * while protocol handlers process asynchronous callbacks. Most mutating operations are synchronized
 * on the cache instance so readers can safely reuse the same instance across threads; {@link
 * #updateCompressionStatus(String, COMPRESS_STATE)} and {@link #setPriority(String, short)} rely on
 * callers to provide any external ordering they require. Missing identifiers are treated as benign
 * to accommodate races between completion and cancellation.
 *
 * <p>Typical usage is: add a request when it starts, update the status as events arrive, then
 * remove it when it finishes or is canceled. Secondary indexes are pruned in tandem, so lookup by
 * URI never returns stale entries. The class does not persist data; callers should rebuild it after
 * the node restarts. Because it holds live {@code RequestStatus} objects, consumers should avoid
 * long-lived references outside synchronized blocks unless they copy them via {@link #addTo(List)}.
 *
 * <ul>
 *   <li>Provides fast lookup by identifier for all request kinds.
 *   <li>Keeps auxiliary maps in sync for download and upload specific flows.
 *   <li>Tolerates duplicate removals and late updates without throwing.
 * </ul>
 *
 * @see RequestStatus
 * @see DownloadRequestStatus
 * @see UploadRequestStatus
 */
public class RequestStatusCache {
  private static final Logger LOG = LoggerFactory.getLogger(RequestStatusCache.class);

  private final Map<String, RequestStatus> requestsByIdentifier;
  private final MultiValueTable<FreenetURI, DownloadRequestStatus> downloadsByURI;
  private final MultiValueTable<FreenetURI, RequestStatus> uploadsByFinalURI;

  RequestStatusCache() {
    requestsByIdentifier = new HashMap<>();
    downloadsByURI = new MultiValueTable<>();
    uploadsByFinalURI = new MultiValueTable<>();
  }

  synchronized void addDownload(DownloadRequestStatus status) {
    RequestStatus old = requestsByIdentifier.put(status.getIdentifier(), status);
    if (LOG.isDebugEnabled()) LOG.debug("Starting download {}", status.getIdentifier());
    if (old == status) return;
    downloadsByURI.put(status.getURI(), status);
  }

  synchronized void addUpload(UploadRequestStatus status) {
    RequestStatus old = requestsByIdentifier.put(status.getIdentifier(), status);
    if (old == status) return;
    if (LOG.isDebugEnabled()) LOG.debug("Starting upload {}", status.getIdentifier());
    FreenetURI uri = status.getURI();
    if (uri != null) uploadsByFinalURI.put(uri, status);
  }

  synchronized void finishedDownload(
      String identifier, boolean success, DownloadOutcomeInfo outcome) {
    DownloadRequestStatus status = (DownloadRequestStatus) requestsByIdentifier.get(identifier);
    if (status == null) return; // Can happen during cancel etc.
    status.setFinished(success, outcome);
  }

  synchronized void gotFinalURI(String identifier, FreenetURI finalURI) {
    UploadRequestStatus status = (UploadRequestStatus) requestsByIdentifier.get(identifier);
    if (status == null) return; // Can happen during cancel etc.
    if (status.getFinalURI() == null)
      // No final URI set yet, put into the index.
      uploadsByFinalURI.put(finalURI, status);
    status.setFinalURI(finalURI);
  }

  synchronized void finishedUpload(
      String identifier,
      boolean success,
      FreenetURI finalURI,
      InsertExceptionMode failureCode,
      String failureReasonShort,
      String failureReasonLong) {
    UploadRequestStatus status = (UploadRequestStatus) requestsByIdentifier.get(identifier);
    if (status == null) return; // Can happen during cancel etc.
    if (status.getFinalURI() == null && finalURI != null)
      // No final URI set yet, put into the index.
      uploadsByFinalURI.put(finalURI, status);
    status.setFinished(success, finalURI, failureCode, failureReasonShort, failureReasonLong);
  }

  synchronized void updateStatus(String identifier, SplitfileProgressEvent event) {
    RequestStatus status = requestsByIdentifier.get(identifier);
    if (status == null) return; // Can happen during cancel etc.
    status.updateStatus(event);
  }

  synchronized void updateDetectedCompatModes(
      String identifier,
      FcpCompatibilityMode[] compatModes,
      byte[] splitfileKey,
      boolean dontCompress) {
    DownloadRequestStatus status = (DownloadRequestStatus) requestsByIdentifier.get(identifier);
    if (status == null) return; // Can happen during cancel etc.
    status.updateDetectedCompatModes(compatModes, dontCompress);
    status.updateDetectedSplitfileKey(splitfileKey);
  }

  synchronized void removeByIdentifier(String identifier) {
    RequestStatus status = requestsByIdentifier.remove(identifier);
    if (status == null) return; // Already removed or never existed.
    switch (status) {
      case DownloadRequestStatus requestStatus1 -> {
        FreenetURI uri = status.getURI();
        assert (uri != null);
        downloadsByURI.removeElement(uri, requestStatus1);
      }
      case UploadRequestStatus requestStatus -> {
        FreenetURI uri = requestStatus.getFinalURI();
        if (uri != null) uploadsByFinalURI.removeElement(uri, status);
      }
      default -> {
        // Other RequestStatus implementations have no additional indexes to update.
      }
    }
  }

  synchronized void clear() {
    requestsByIdentifier.clear();
    downloadsByURI.clear();
    uploadsByFinalURI.clear();
  }

  /**
   * Updates the compression phase for an upload request if it is still tracked.
   *
   * <p>The method is intentionally unsynchronized because it only touches a single status instance
   * and is expected to be called from the same thread that initiated the upload. If the identifier
   * is unknown, the call is ignored, allowing callers to send speculative or late updates without
   * raising errors. Compression state transitions should follow the sequence defined by {@link
   * ClientPut.COMPRESS_STATE}; no validation is enforced here.
   *
   * @param identifier identifier of the upload being compressed; must reference an active entry to
   *     have any effect.
   * @param compressing the new compression state describing the current stage; values come from the
   *     FCP client pipeline and are not null-checked here.
   */
  public void updateCompressionStatus(String identifier, COMPRESS_STATE compressing) {
    UploadFileRequestStatus status = (UploadFileRequestStatus) requestsByIdentifier.get(identifier);
    if (status == null) return; // Can happen during cancel etc.
    status.updateCompressionStatus(compressing);
  }

  /**
   * Copies current request snapshots into the supplied collection without exposing internal
   * instances.
   *
   * <p>The method iterates over all cached entries under the cache lock, clones each via {@link
   * RequestStatus#copy()}, and appends them to the provided list. It enables user interfaces to
   * render progress without retaining locks for the duration of the render cycle. The target list
   * is not cleared, so callers may accumulate historical states if they reuse the same list across
   * invocations. Null identifiers are ignored implicitly because the cache never stores them.
   *
   * @param status mutable collection that receives copies of every tracked request; must accept the
   *     added elements.
   */
  public synchronized void addTo(List<RequestStatus> status) {
    // The copy allows rendering without holding the cache lock for the entire UI render.
    for (RequestStatus req : requestsByIdentifier.values()) status.add(req.copy());
  }

  /**
   * Updates the expected MIME type for a pending download if it remains present in the cache.
   *
   * <p>The method is tolerant of late notifications; when the identifier is no longer tracked, it
   * returns silently. Callers typically invoke this after metadata discovery but before final data
   * delivery so UI components can present a more accurate content type. The provided MIME string is
   * stored as-is; callers should supply normalized values when necessary.
   *
   * @param identifier request identifier supplied by the client; must not be {@code null}.
   * @param foundDataMimeType MIME type detected during fetch; may be any well-formed value.
   */
  public synchronized void updateExpectedMIME(String identifier, String foundDataMimeType) {
    DownloadRequestStatus status = (DownloadRequestStatus) requestsByIdentifier.get(identifier);
    if (status == null) return; // Can happen during cancel etc.
    status.updateExpectedMIME(foundDataMimeType);
  }

  /**
   * Records the expected data length for an in-flight download so progress bars can estimate work.
   *
   * <p>If the identifier is missing, the method exits without side effects, enabling callers to
   * send redundant or late updates safely. The value is interpreted as bytes; negative values are
   * not rejected here but may be validated downstream by {@link DownloadRequestStatus}.
   *
   * @param identifier request identifier whose download metadata is being updated; non-null.
   * @param expectedDataLength expected byte length of the payload; callers should supply
   *     non-negative values.
   */
  public synchronized void updateExpectedDataLength(String identifier, long expectedDataLength) {
    DownloadRequestStatus status = (DownloadRequestStatus) requestsByIdentifier.get(identifier);
    if (status == null) return; // Can happen during cancel etc.
    status.updateExpectedDataLength(expectedDataLength);
  }

  /**
   * Adjusts the priority class of a tracked request when it is still present in the cache.
   *
   * <p>This method is intentionally lightweight and not synchronized; callers invoking it from
   * multiple threads should serialize calls if they need deterministic ordering. If the identifier
   * is unknown, the call is ignored to avoid surfacing races between completion and priority
   * updates.
   *
   * @param identifier request identifier to reprioritize; must refer to an active request.
   * @param newPriorityClass priority class value accepted by the underlying client; see caller docs
   *     for valid ranges.
   */
  public void setPriority(String identifier, short newPriorityClass) {
    RequestStatus status = requestsByIdentifier.get(identifier);
    if (status == null) return; // Can happen during cancel etc.
    status.setPriority(newPriorityClass);
  }

  /**
   * Restart a request. Caller should call, false first, at which point we setStarted, and, true
   * when it has actually started (a race condition means we don't setStarted at that point since
   * it's possible the success/failure callback might happen first).
   *
   * <p>The boolean overload clears finished state when invoked with {@code false} and marks the
   * request as started when invoked with {@code true}. It tolerates late or duplicate updates by
   * ignoring identifiers that are no longer tracked. All mutations are serialized on the cache
   * lock, so callers can safely use the same cache across worker and UI threads.
   *
   * @param identifier request identifier being restarted; must be non-null and match a cached entry
   *     to take effect.
   * @param started flag indicating whether the request is now considered started ({@code true}) or
   *     being reset prior to start ({@code false}).
   */
  public synchronized void updateStarted(String identifier, boolean started) {
    RequestStatus status = requestsByIdentifier.get(identifier);
    if (status == null) return; // Can happen during cancel etc.

    if (!started)
      // Caller should call with false first, so we only need to unset finished when setting
      // started=false.
      status.restart(false);
    else
      // Already restarted, just set started = true.
      status.setStarted(true);
  }

  /**
   * Restart a download. Caller should call, false first, at which point we setStarted, and, true
   * when it has actually started (a race condition means we don't setStarted at that point since
   * it's possible the success/failure callback might happen first).
   *
   * <p>This overload restarts the request and updates the download URI when a redirect is followed.
   * It removes the old URI from the secondary index, applies the redirect, and re-registers the
   * request under the new key. Absent identifiers are ignored to remain resilient to races between
   * redirect handling and cancellation.
   *
   * @param identifier request identifier being restarted after a redirect; non-null for cache hits.
   * @param redirect new target URI if the request was redirected; may be {@code null} to skip URI
   *     remapping.
   */
  public synchronized void updateStarted(String identifier, FreenetURI redirect) {
    DownloadRequestStatus status = (DownloadRequestStatus) requestsByIdentifier.get(identifier);
    if (status == null) return; // Can happen during cancel etc.
    status.restart(false);
    if (redirect != null) {
      downloadsByURI.remove(status.getURI());
      status.redirect(redirect);
      downloadsByURI.put(redirect, status);
    }
  }

  /**
   * Returns a cached download bucket that already holds data for the given URI when it is usable.
   *
   * <p>The method scans all download entries indexed by the supplied key and returns the first that
   * contains non-empty data meeting the caller's filter expectations. It wraps the bucket in {@link
   * NoFreeBucket} to prevent caller-driven free operations from disturbing shared buffers. When no
   * suitable entry exists the method returns {@code null}. Callers should treat the returned bucket
   * as read-only and respect the {@code filterData} flag conveyed in the {@link CacheFetchResult}.
   *
   * @param key URI used to locate matching downloads in the cache; must not be {@code null}.
   * @param noFilter when {@code true}, only returns data that did not request filtering during
   *     download; otherwise filtered data may be returned.
   * @return a {@link CacheFetchResult} wrapping a shadow bucket and metadata, or {@code null} when
   *     no cached data fits the criteria.
   */
  public synchronized CacheFetchResult getShadowBucket(FreenetURI key, boolean noFilter) {
    for (DownloadRequestStatus download : downloadsByURI.getAllAsList(key)) {
      Bucket data = download.getDataShadow();
      boolean hasData = data != null && data.size() > 0;
      boolean filterAllowed = !(noFilter && download.filterData);
      boolean dataTypeMatches = !download.overriddenDataType;
      if (hasData && filterAllowed && dataTypeMatches) {
        return new CacheFetchResult(
            new ClientMetadata(download.getMIMEType()),
            new NoFreeBucket(data),
            download.filterData);
      }
    }
    return null;
  }
}

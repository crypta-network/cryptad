package network.crypta.clients.fcp;

import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.keys.FreenetURI;

/**
 * Represents the cached, queryable status of a client upload handled through the FCP interface.
 *
 * <p>Instances of this class mirror the life-cycle of {@link ClientRequest} objects: they persist
 * identifiers, byte counts, timing information, and the last known outcome so user interfaces and
 * monitoring endpoints can present progress even after a restart. A status object can be queried at
 * any time to determine whether an insert has started, whether it finished successfully, and which
 * human-readable explanations should be surfaced when failures happened.
 *
 * <p>The state captured here is mutable for as long as the upload proceeds. Callers must expect the
 * fields to change concurrently as worker threads finalize inserts or propagate fatal errors. This
 * class therefore exposes synchronized accessors for the derived URI data while leaving other
 * counters to be managed by {@link RequestStatus}. Consumers should treat the exposed references as
 * snapshots rather than authoritative handles and re-query when presenting long-running UI flows.
 *
 * <ul>
 *   <li>Tracks both the desired target URI and the final published URI.
 *   <li>Records summary and verbose failure descriptions.
 *   <li>Provides helper logic for deriving a preferred filename for client dialogs.
 * </ul>
 *
 * <pre>{@code
 * UploadRequestStatus status = cache.lookup(identifier);
 * if (status.getFinalURI() != null) {
 *   ui.showResult(status.getFinalURI());
 * }
 * }</pre>
 *
 * @see RequestStatus
 */
public abstract class UploadRequestStatus extends RequestStatus {

  private FreenetURI finalURI;
  private final FreenetURI targetURI;
  private InsertExceptionMode failureCode;
  private String failureReasonShort;
  private String failureReasonLong;

  /**
   * Creates an upload status entry from bundled request snapshots.
   *
   * @param statusSnapshot base request counters and timestamps.
   * @param details upload-specific URI and failure metadata.
   */
  UploadRequestStatus(RequestStatusSnapshot statusSnapshot, UploadRequestStatusDetails details) {
    super(statusSnapshot);
    this.finalURI = details.finalURI();
    this.targetURI = details.targetURI();
    this.failureCode = details.failureCode();
    this.failureReasonShort = details.failureReasonShort();
    this.failureReasonLong = details.failureReasonLong();
  }

  /**
   * Initializes a new status instance that mirrors the values contained in another entry.
   *
   * <p>This copy constructor is primarily used when code needs to offer callers a detached snapshot
   * while keeping the original object mutable for internal bookkeeping. The source status is read
   * once at construction time, so future mutations applied to either instance do not propagate to
   * the other. This is useful when a status is inserted into caches or published to remote clients
   * and should no longer be affected by worker-thread updates.
   *
   * @param source status entry to duplicate, typically the live, mutable record managed internally
   */
  protected UploadRequestStatus(UploadRequestStatus source) {
    super(source);
    this.finalURI = source.finalURI;
    this.targetURI = source.targetURI;
    this.failureCode = source.failureCode;
    this.failureReasonShort = source.failureReasonShort;
    this.failureReasonLong = source.failureReasonLong;
  }

  synchronized void setFinished(
      boolean success,
      FreenetURI finalURI,
      InsertExceptionMode failureCode,
      String failureReasonShort,
      String failureReasonLong) {
    setFinished(success);
    this.finalURI = finalURI;
    this.failureCode = failureCode;
    this.failureReasonShort = failureReasonShort;
    this.failureReasonLong = failureReasonLong;
  }

  /**
   * Returns the URI that was ultimately published by the upload, if a value exists yet.
   *
   * <p>The reference represents the canonical URI under which the inserted data became available.
   * When the upload is still running or failed before committing, the value may be {@code null} and
   * callers should fall back to {@link #getTargetURI()}. Thread-safety is guaranteed through the
   * synchronized accessor because the URI is frequently updated by worker threads upon completion
   * or retry of an insert.
   *
   * @return immutable {@link FreenetURI} describing the published location, or {@code null} when
   *     the upload has not produced a final handle
   */
  public synchronized FreenetURI getFinalURI() {
    return finalURI;
  }

  /**
   * Provides the originally requested URI, allowing clients to distinguish intent from outcomes.
   *
   * <p>This value is stable for the lifetime of the status entry and typically represents the key
   * chosen by the user or remote caller. Even when {@link #getFinalURI()} returns {@code null}, the
   * target value helps diagnose routing decisions, index selections, and access rights. It is never
   * modified after construction, so the returned instance can safely be cached or inspected without
   * extra synchronization.
   *
   * @return immutable {@link FreenetURI} representing the user-requested target, or {@code null} if
   *     the request was synthesized without a specific key
   */
  public FreenetURI getTargetURI() {
    return targetURI;
  }

  /**
   * Retrieves the URI that best reflects the current completion state for this upload.
   *
   * <p>The method first consults {@link #getFinalURI()} to surface a completed handle and falls
   * back to the target URI if no final value is yet available. Callers that only need a single URI
   * to display can use this helper instead of performing the null-check logic themselves. The
   * returned reference must be treated as a snapshot, because concurrent updates may expose a final
   * URI after this method returns.
   *
   * @return {@link FreenetURI} reporting either the finalized or intended key, or {@code null} when
   *     neither exists
   */
  @Override
  public FreenetURI getURI() {
    return getFinalURI();
  }

  /**
   * Reports the size of the payload that this upload attempts to publish, expressed in bytes.
   *
   * <p>Implementations should provide the best-known estimate so that progress meters and client
   * heuristics can reason about completion ratios. The value may be final, rounded, or only an
   * early guess depending on how the derived subclass acquires metadata. Callers should therefore
   * treat it as advisory and may re-query if the associated {@link ClientRequest} enumerates
   * additional segments later in its life-cycle.
   *
   * @return positive byte count describing content length, or zero when no estimate exists yet
   */
  @Override
  public abstract long getDataSize();

  /**
   * Obtains the most recent textual explanation describing why the upload failed or stalled.
   *
   * <p>The status maintains both concise and expanded variants so different presentation layers can
   * select an appropriate verbosity. The short text typically fits notifications or compact tables,
   * while the long text is suitable for logs, REST responses, or troubleshooting dialogs. Messages
   * are updated whenever the associated request transitions into a fatal state, so callers should
   * not cache the result unless they also snapshot the surrounding {@link RequestStatus} fields.
   *
   * @param longDescription {@code true} to request the expanded explanation, {@code false} for the
   *     concise human-readable summary
   * @return descriptive message conveying the observed failure, or {@code null} when no failure is
   *     recorded yet
   */
  @Override
  public String getFailureReason(boolean longDescription) {
    return longDescription ? failureReasonLong : failureReasonShort;
  }

  synchronized void setFinalURI(FreenetURI finalURI2) {
    this.finalURI = finalURI2;
  }

  /**
   * Suggests a filename derived from the known URIs for display in client save dialogs.
   *
   * <p>The method inspects the final URI first to honor any filenames assigned by the completed
   * insert, including meta strings distributed through Freenet. If the upload has not produced a
   * final URI, it falls back to the target URI so callers can still infer a meaningful label, for
   * example when pre-populating a download request. No normalization is performed beyond delegating
   * to {@link FreenetURI#getPreferredFilename()}, therefore callers should sanitize values before
   * writing them to disk.
   *
   * @return filename hint derived from meta strings or doc names, or {@code null} when neither URI
   *     contains sufficient metadata
   */
  @Override
  public String getPreferredFilename() {
    FreenetURI uri = getFinalURI();
    if (uri != null && (uri.hasMetaStrings() || uri.getDocName() != null))
      return uri.getPreferredFilename();
    uri = getTargetURI();
    if (uri != null && (uri.hasMetaStrings() || uri.getDocName() != null))
      return uri.getPreferredFilename();
    return null;
  }
}

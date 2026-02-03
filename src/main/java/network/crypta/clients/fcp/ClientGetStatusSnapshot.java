package network.crypta.clients.fcp;

import java.io.File;
import java.time.Instant;
import java.util.Arrays;
import network.crypta.client.FetchContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.jetbrains.annotations.NotNull;

/**
 * Represents an immutable status snapshot for a {@link ClientGet} request.
 *
 * <p>This class aggregates the values needed to build a {@link DownloadRequestStatus} at a single
 * point in time. Callers typically construct one instance while preparing an FCP status reply, then
 * pass it to the formatter or status builder that emits the response. The snapshot does not
 * validate or normalize any inputs; it is a thin, immutable carrier that preserves whatever values
 * the request has recorded at that moment.
 *
 * <p>All fields are stored verbatim, including arrays and buckets, and no defensive copies are
 * created. As a result, callers must treat any referenced objects and arrays as read-only for the
 * lifetime of the snapshot. Equality and hash code computations include array contents, so mutating
 * arrays after construction can change equality and hash semantics. Thread-safety is therefore tied
 * to the referenced objects and their usage by the caller.
 *
 * <ul>
 *   <li>Aggregates identifiers, lifecycle state, and progress counters from the request.
 *   <li>Captures data destination, length, and MIME type hints for download reporting.
 *   <li>Preserves fetch context and compatibility metadata needed by status encoders.
 * </ul>
 *
 * @see ClientGet
 * @see DownloadRequestStatus
 */
public final class ClientGetStatusSnapshot {
  private final RequestStatusSnapshot statusSnapshot;
  private final DownloadProgressSnapshot progressSnapshot;
  private final DownloadDataSnapshot dataSnapshot;
  private final DownloadContextSnapshot contextSnapshot;

  /**
   * Creates a snapshot containing the current request metadata.
   *
   * <p>This constructor stores the supplied values without validation or copying, so the snapshot
   * reflects a coherent view of the request at the moment a status response is prepared. Reference
   * parameters may be {@code null} when the corresponding data is unknown or not applicable; the
   * snapshot forwards those {@code null} values to downstream status encoders without
   * interpretation. The instance is immutable, but the referenced objects may still be mutable and
   * should be treated as read-only once the snapshot is shared.
   *
   * <pre>{@code
   * ClientGetStatusSnapshot snapshot =
   *     new ClientGetStatusSnapshot(statusSnapshot, progressSnapshot, dataSnapshot, contextSnapshot);
   * }</pre>
   *
   * @param statusSnapshot core lifecycle and progress counters for the request, stored as-is
   * @param progressSnapshot cached progress and failure details, possibly {@code null}
   * @param dataSnapshot discovered data MIME, length, and storage destinations, possibly {@code
   *     null}
   * @param contextSnapshot fetch context and compatibility metadata used for status output
   */
  public ClientGetStatusSnapshot(
      RequestStatusSnapshot statusSnapshot,
      DownloadProgressSnapshot progressSnapshot,
      DownloadDataSnapshot dataSnapshot,
      DownloadContextSnapshot contextSnapshot) {
    this.statusSnapshot = statusSnapshot;
    this.progressSnapshot = progressSnapshot;
    this.dataSnapshot = dataSnapshot;
    this.contextSnapshot = contextSnapshot;
  }

  static RequestStatusSnapshot buildRequestStatusSnapshot(
      String identifier,
      ClientRequest.Persistence persistence,
      boolean started,
      boolean finished,
      boolean succeeded,
      SimpleProgressMessage progressPending,
      short priorityClass) {
    boolean totalFinalized = false;
    int total = 0;
    int min = 0;
    int fetched = 0;
    int fatal = 0;
    int failed = 0;
    // See ClientRequester.getLatestSuccess() for why this defaults to the current time.
    Instant latestSuccess = Instant.now();
    Instant latestFailure = null;

    if (progressPending != null) {
      totalFinalized = progressPending.isTotalFinalized();
      // The progress API reports doubles to preserve partial block counts from the splitter.
      total = (int) progressPending.getTotalBlocks();
      min = (int) progressPending.getMinBlocks();
      fetched = (int) progressPending.getFetchedBlocks();
      latestSuccess = progressPending.getLatestSuccess();
      fatal = (int) progressPending.getFatalyFailedBlocks();
      failed = (int) progressPending.getFailedBlocks();
      latestFailure = progressPending.getLatestFailure();
    }
    if (finished && succeeded) totalFinalized = true;
    return new RequestStatusSnapshot(
        identifier,
        persistence,
        started,
        finished,
        succeeded,
        total,
        min,
        fetched,
        latestSuccess,
        fatal,
        failed,
        latestFailure,
        totalFinalized,
        priorityClass);
  }

  /**
   * Returns the request identifier reported to the client.
   *
   * <p>The identifier is typically client-provided and used to correlate status responses with the
   * initiating request. The snapshot stores the value verbatim and does not normalize or validate
   * it in any way. A {@code null} identifier is permitted when the request has not yet recorded or
   * exposed its identifier, and that {@code null} will be propagated to downstream encoders.
   *
   * @return the request identifier, or {@code null} when the request has not set one
   */
  public String identifier() {
    return statusSnapshot.identifier();
  }

  /**
   * Returns the persistence mode for the request.
   *
   * <p>The persistence value indicates how the request survives restarts or disconnects, and it is
   * passed through without interpretation. A {@code null} value is allowed when persistence was not
   * specified or is otherwise unavailable at snapshot creation time. The returned value is owned by
   * the caller of the snapshot and should be treated as read-only metadata.
   *
   * @return the persistence mode, or {@code null} when no persistence policy is recorded
   */
  public ClientRequest.Persistence persistence() {
    return statusSnapshot.persistence();
  }

  /**
   * Indicates whether the request has started.
   *
   * <p>This flag captures the most recent start state at snapshot creation time. It does not imply
   * completion and may remain {@code true} for the remainder of the request lifetime once execution
   * begins. The snapshot does not compute or adjust this value; it simply reports what the request
   * recorded at the moment the snapshot was built.
   *
   * @return {@code true} when the request has started, {@code false} otherwise
   */
  public boolean started() {
    return statusSnapshot.started();
  }

  /**
   * Indicates whether the request has finished.
   *
   * <p>A finished request has reached a terminal state and will not make further progress. When
   * this value is {@code true}, the {@link #succeeded()} flag describes whether completion was
   * successful or failed. This value is a snapshot of the request state and does not imply any
   * future behavior beyond the recorded terminal state.
   *
   * @return {@code true} when the request has finished, {@code false} otherwise
   */
  public boolean finished() {
    return statusSnapshot.finished();
  }

  /**
   * Indicates whether the request has succeeded.
   *
   * <p>This flag is primarily meaningful when {@link #finished()} is {@code true}; before
   * completion it may represent an in-progress or default value. When a request fails, the failure
   * details are typically available through {@link #failedMessage()}. The snapshot does not
   * reconcile or infer success; it reports the value recorded by the request.
   *
   * @return {@code true} when the request completed successfully, {@code false} otherwise
   */
  public boolean succeeded() {
    return statusSnapshot.success();
  }

  /**
   * Returns the most recently recorded progress message, if any.
   *
   * <p>The progress message provides a point-in-time view of in-flight work. It can be {@code null}
   * when no progress has been recorded, when the request has already completed, or when the request
   * does not emit incremental progress. The snapshot does not clone the message, so callers must
   * not mutate it if it is shared across threads.
   *
   * @return the last progress message, or {@code null} when no progress is available
   */
  public SimpleProgressMessage progressPending() {
    return progressSnapshot.progressPending();
  }

  /**
   * Returns the cached failure message if the request failed.
   *
   * <p>This value is {@code null} when no failure is known or when the request has not yet reached
   * a terminal failure state. The snapshot does not derive or validate failure details; it simply
   * stores and returns the provided message object. Callers should treat the returned message as
   * read-only because it is not defensively copied.
   *
   * @return the failure message, or {@code null} when no failure has been recorded
   */
  public GetFailedMessage failedMessage() {
    return progressSnapshot.failedMessage();
  }

  /**
   * Returns the MIME type discovered for the data.
   *
   * <p>The MIME type is a hint derived from request processing and may be {@code null} when not yet
   * known or when no detection was performed. The snapshot does not normalize, validate, or
   * canonicalize the value; it forwards exactly what was recorded. Consumers should therefore apply
   * their own validation if they require a strict MIME format.
   *
   * @return the discovered MIME type, or {@code null} when it is not available
   */
  public String foundDataMimeType() {
    return dataSnapshot.foundDataMimeType();
  }

  /**
   * Returns the recorded data length for the request.
   *
   * <p>The length is expressed in bytes and reflects the latest known size at snapshot creation
   * time. A value of {@code 0} may indicate an unknown length or an empty payload, depending on the
   * calling context and request type. The snapshot does not interpret or clamp this value; it
   * simply returns the stored value for downstream status formatting.
   *
   * @return the recorded data length in bytes, possibly zero when unknown or empty
   */
  public long foundDataLength() {
    return dataSnapshot.foundDataLength();
  }

  /**
   * Returns the destination file for disk-based requests.
   *
   * <p>The file reference is optional and may be {@code null} for in-memory requests or when the
   * destination has not been assigned. The snapshot does not check file existence, permissions, or
   * path validity; it simply returns the stored reference. Callers should treat the returned value
   * as read-only metadata rather than an authoritative file system guarantee.
   *
   * @return the destination file, or {@code null} when no file target is applicable
   */
  public File destinationFile() {
    return dataSnapshot.destinationFile();
  }

  /**
   * Returns the bucket containing result data.
   *
   * <p>The bucket is optional and may be {@code null} when data is not yet available or when the
   * request is configured to stream results elsewhere. No ownership transfer occurs; callers remain
   * responsible for bucket lifecycle management and must not assume the bucket is immutable. The
   * snapshot simply forwards the reference as recorded.
   *
   * @return the result data bucket, or {@code null} when no data bucket is available
   */
  public Bucket dataBucket() {
    return dataSnapshot.dataBucket();
  }

  /**
   * Returns the fetch context used for the request.
   *
   * <p>The context can include MIME overrides, filter settings, and other request-scoped options.
   * The snapshot stores the reference as provided and does not copy or validate it. A {@code null}
   * value is permitted when a context is not available, and consumers should handle that case by
   * falling back to their own defaults.
   *
   * @return the fetch context, or {@code null} when no context is available
   */
  public FetchContext fetchContext() {
    return contextSnapshot.fetchContext();
  }

  /**
   * Returns the scheduler priority class for the request.
   *
   * <p>The value is stored verbatim and is interpreted by the request scheduler. This snapshot does
   * not enforce any valid range, clamp values, or normalize the priority; it simply reports what
   * was recorded at snapshot creation time. Consumers should therefore avoid making assumptions
   * beyond their scheduler's documented priority semantics.
   *
   * @return the priority class as a short value, reported exactly as recorded
   */
  public short priorityClass() {
    return statusSnapshot.priority();
  }

  /**
   * Returns the compatibility modes observed for the request.
   *
   * <p>The returned array is the original reference supplied to the constructor. It may be {@code
   * null} or empty, and no defensive copy is made. Callers should therefore treat the array as
   * read-only to avoid affecting equality or hash-based collections. The snapshot does not sort or
   * deduplicate the modes.
   *
   * @return the compatibility mode array, or {@code null} when no modes were recorded
   */
  public CompatibilityMode[] compatModes() {
    return contextSnapshot.compatModes();
  }

  /**
   * Returns the splitfile crypto key override, if any.
   *
   * <p>The returned array is not copied. It may be {@code null} when no override is configured, and
   * callers should avoid mutating the array after snapshot construction. Any mutation can change
   * the snapshot's equality and hash semantics because array contents are included in comparisons.
   *
   * @return the splitfile key bytes, or {@code null} when no override is configured
   */
  public byte[] splitfileKey() {
    return contextSnapshot.splitfileKey();
  }

  /**
   * Returns the request URI associated with this snapshot.
   *
   * <p>The URI may be {@code null} when the request has not yet resolved a definitive URI or when
   * the caller chooses not to expose it. The snapshot does not validate or normalize the URI and
   * does not resolve redirects; it simply returns the stored reference. Consumers should treat the
   * value as a hint rather than a guaranteed canonical URI.
   *
   * @return the request URI, or {@code null} when no URI is available
   */
  public FreenetURI uri() {
    return contextSnapshot.uri();
  }

  /**
   * Indicates whether reinsertion should skip compression.
   *
   * <p>This flag is reported to the status encoder to reflect the caller's reinsertion policy. It
   * does not influence any other values held in this snapshot and is not derived from other fields.
   * The snapshot simply preserves the value set by the request at snapshot creation time.
   *
   * @return {@code true} when reinsertion should skip compression, {@code false} otherwise
   */
  public boolean dontCompress() {
    return contextSnapshot.dontCompress();
  }

  RequestStatusSnapshot statusSnapshot() {
    return statusSnapshot;
  }

  /**
   * Compares this snapshot with another object for value equality.
   *
   * <p>Equality requires all scalar fields to match, as well as array contents for compatibility
   * modes and splitfile key data. Because the arrays are not defensively copied, mutating their
   * contents after construction can change equality results over time. The method is deterministic
   * as long as the referenced arrays and objects are not mutated during comparison.
   *
   * @param other object to compare against, possibly {@code null} and of another type
   * @return {@code true} when all fields and array contents are equal, otherwise {@code false}
   */
  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof ClientGetStatusSnapshot otherSnapshot)) {
      return false;
    }
    return started() == otherSnapshot.started()
        && finished() == otherSnapshot.finished()
        && succeeded() == otherSnapshot.succeeded()
        && foundDataLength() == otherSnapshot.foundDataLength()
        && priorityClass() == otherSnapshot.priorityClass()
        && dontCompress() == otherSnapshot.dontCompress()
        && java.util.Objects.equals(identifier(), otherSnapshot.identifier())
        && persistence() == otherSnapshot.persistence()
        && java.util.Objects.equals(progressPending(), otherSnapshot.progressPending())
        && java.util.Objects.equals(failedMessage(), otherSnapshot.failedMessage())
        && java.util.Objects.equals(foundDataMimeType(), otherSnapshot.foundDataMimeType())
        && java.util.Objects.equals(destinationFile(), otherSnapshot.destinationFile())
        && java.util.Objects.equals(dataBucket(), otherSnapshot.dataBucket())
        && java.util.Objects.equals(fetchContext(), otherSnapshot.fetchContext())
        && Arrays.equals(compatModes(), otherSnapshot.compatModes())
        && Arrays.equals(splitfileKey(), otherSnapshot.splitfileKey())
        && java.util.Objects.equals(uri(), otherSnapshot.uri());
  }

  /**
   * Computes a hash code from all stored snapshot fields.
   *
   * <p>The hash includes the contents of the compatibility mode and splitfile key arrays, keeping
   * it consistent with {@link #equals(Object)}. Because those arrays are not copied, mutating their
   * contents after construction can change the hash value. Avoid using this instance as a map key
   * if the underlying arrays are expected to change.
   *
   * @return a hash code derived from all snapshot fields and array contents
   */
  @Override
  public int hashCode() {
    int result =
        java.util.Objects.hash(
            identifier(),
            persistence(),
            started(),
            finished(),
            succeeded(),
            progressPending(),
            failedMessage(),
            foundDataMimeType(),
            foundDataLength(),
            destinationFile(),
            dataBucket(),
            fetchContext(),
            priorityClass(),
            uri(),
            dontCompress());
    result = 31 * result + Arrays.hashCode(compatModes());
    result = 31 * result + Arrays.hashCode(splitfileKey());
    return result;
  }

  /**
   * Returns a diagnostic string representation of this snapshot.
   *
   * <p>The string includes scalar values and full {@link Arrays#toString(byte[])} output for
   * arrays. Because it may include identifiers and key material, it should be used with care in
   * production logs or user-visible output. The formatting is intended for debugging and should not
   * be parsed or treated as a stable serialization format.
   *
   * @return a human-readable representation intended for diagnostic use only
   */
  @Override
  public @NotNull String toString() {
    //noinspection resource
    return "ClientGetStatusSnapshot["
        + "identifier="
        + identifier()
        + ", persistence="
        + persistence()
        + ", started="
        + started()
        + ", finished="
        + finished()
        + ", succeeded="
        + succeeded()
        + ", progressPending="
        + progressPending()
        + ", failedMessage="
        + failedMessage()
        + ", foundDataMimeType="
        + foundDataMimeType()
        + ", foundDataLength="
        + foundDataLength()
        + ", destinationFile="
        + destinationFile()
        + ", dataBucket="
        + dataBucket()
        + ", fetchContext="
        + fetchContext()
        + ", priorityClass="
        + priorityClass()
        + ", compatModes="
        + Arrays.toString(compatModes())
        + ", splitfileKey="
        + Arrays.toString(splitfileKey())
        + ", uri="
        + uri()
        + ", dontCompress="
        + dontCompress()
        + ']';
  }
}

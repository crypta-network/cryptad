package network.crypta.clients.fcp;

import java.io.File;
import java.util.Arrays;
import network.crypta.client.FetchContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.jetbrains.annotations.NotNull;

/**
 * Parameter bundle describing a {@link ClientGet} request status snapshot.
 *
 * <p>This type captures the data required to construct a {@link DownloadRequestStatus} from the
 * current state of a {@link ClientGet} request. It is intentionally immutable and performs no
 * validation, so callers can reuse it across status refreshes without altering behavior. Typical
 * usage is to assemble one instance when a status reply is being generated, then pass it through
 * the formatting layer that emits the FCP response.
 *
 * <p>All fields are stored verbatim, including arrays and buckets; no defensive copies are made.
 * Callers should therefore treat contained arrays and referenced objects as read-only for the
 * lifetime of the snapshot. Equality and hash code calculations include array contents, so mutating
 * arrays after construction can destabilize hashing and comparisons. The instance is thread-safe
 * only if all referenced objects are used in a thread-safe manner by the caller.
 *
 * <ul>
 *   <li>Aggregates request identifiers, progress, and failure details.
 *   <li>Captures data destination, length, and MIME type hints.
 *   <li>Includes fetch context and compatibility metadata used for status output.
 * </ul>
 *
 * @see ClientGet
 * @see DownloadRequestStatus
 */
@SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
public final class ClientGetStatusSnapshot {
  private final String identifier;
  private final ClientRequest.Persistence persistence;
  private final boolean started;
  private final boolean finished;
  private final boolean succeeded;
  private final SimpleProgressMessage progressPending;
  private final GetFailedMessage failedMessage;
  private final String foundDataMimeType;
  private final long foundDataLength;
  private final File destinationFile;
  private final Bucket dataBucket;
  private final FetchContext fetchContext;
  private final short priorityClass;
  private final CompatibilityMode[] compatModes;
  private final byte[] splitfileKey;
  private final FreenetURI uri;
  private final boolean dontCompress;

  /**
   * Creates a snapshot containing the current request metadata.
   *
   * <p>This constructor stores the supplied values without validation or copying. It is intended to
   * be called at the moment a status response is prepared so the snapshot reflects a coherent view
   * of the request. All parameters are optional in the sense that {@code null} values are accepted
   * for reference types; callers should pass {@code null} only when the data is unknown or not
   * applicable to the request type.
   *
   * @param identifier request identifier to report, typically unique per client session
   * @param persistence persistence mode for the request, reflecting its configured lifetime
   * @param started whether the request has started executing or queued work
   * @param finished whether the request has completed, regardless of success
   * @param succeeded whether the request has completed successfully, when finished is true
   * @param progressPending last recorded progress snapshot, or {@code null} if none
   * @param failedMessage cached failure message, or {@code null} when no failure is known
   * @param foundDataMimeType MIME type discovered for the data, or {@code null} if unknown
   * @param foundDataLength data length recorded for the request, in bytes when known
   * @param destinationFile destination file for disk requests, or {@code null} for in-memory data
   * @param dataBucket bucket containing result data, or {@code null} when not yet available
   * @param fetchContext fetch context providing filter and MIME overrides, or {@code null}
   * @param priorityClass scheduler priority class used by the request queue
   * @param compatModes compatibility modes observed for the request, possibly empty or null
   * @param splitfileKey splitfile crypto key override, or {@code null} if not applicable
   * @param uri request URI to report, or {@code null} when not yet resolved
   * @param dontCompress whether reinsertion should skip compression when producing output
   */
  public ClientGetStatusSnapshot(
      String identifier,
      ClientRequest.Persistence persistence,
      boolean started,
      boolean finished,
      boolean succeeded,
      SimpleProgressMessage progressPending,
      GetFailedMessage failedMessage,
      String foundDataMimeType,
      long foundDataLength,
      File destinationFile,
      Bucket dataBucket,
      FetchContext fetchContext,
      short priorityClass,
      CompatibilityMode[] compatModes,
      byte[] splitfileKey,
      FreenetURI uri,
      boolean dontCompress) {
    this.identifier = identifier;
    this.persistence = persistence;
    this.started = started;
    this.finished = finished;
    this.succeeded = succeeded;
    this.progressPending = progressPending;
    this.failedMessage = failedMessage;
    this.foundDataMimeType = foundDataMimeType;
    this.foundDataLength = foundDataLength;
    this.destinationFile = destinationFile;
    this.dataBucket = dataBucket;
    this.fetchContext = fetchContext;
    this.priorityClass = priorityClass;
    this.compatModes = compatModes;
    this.splitfileKey = splitfileKey;
    this.uri = uri;
    this.dontCompress = dontCompress;
  }

  /**
   * Returns the request identifier reported to the client.
   *
   * <p>The identifier is typically client-provided and used to correlate status responses with the
   * initiating request. It is stored verbatim and may be {@code null} when not available.
   *
   * @return the request identifier, or {@code null} if not set
   */
  public String identifier() {
    return identifier;
  }

  /**
   * Returns the persistence mode for the request.
   *
   * <p>The persistence value indicates how the request survives restarts or disconnects. This
   * snapshot does not interpret the value and merely reports it back to the status encoder.
   *
   * @return the persistence mode, or {@code null} if not specified
   */
  public ClientRequest.Persistence persistence() {
    return persistence;
  }

  /**
   * Indicates whether the request has started.
   *
   * <p>This flag captures the most recent start state at snapshot creation time. It does not imply
   * completion, and it may remain {@code true} throughout the entire request lifetime.
   *
   * @return {@code true} if the request has started, {@code false} otherwise
   */
  public boolean started() {
    return started;
  }

  /**
   * Indicates whether the request has finished.
   *
   * <p>A finished request has reached a terminal state. When this value is {@code true}, the {@link
   * #succeeded()} flag describes whether completion was successful.
   *
   * @return {@code true} if the request has finished, {@code false} otherwise
   */
  public boolean finished() {
    return finished;
  }

  /**
   * Indicates whether the request has succeeded.
   *
   * <p>This flag is meaningful primarily when {@link #finished()} is {@code true}. When the request
   * fails, the failure details are usually reported through {@link #failedMessage()}.
   *
   * @return {@code true} if the request succeeded, {@code false} otherwise
   */
  public boolean succeeded() {
    return succeeded;
  }

  /**
   * Returns the most recently recorded progress message, if any.
   *
   * <p>The progress snapshot is an optional view of in-flight work and may be {@code null} when no
   * progress has been recorded or when the request has already completed.
   *
   * @return the last progress message, or {@code null} if none is available
   */
  public SimpleProgressMessage progressPending() {
    return progressPending;
  }

  /**
   * Returns the cached failure message, if the request failed.
   *
   * <p>This value is {@code null} when no failure is known. The snapshot does not derive or
   * validate failure details; it simply stores and returns the provided message object.
   *
   * @return the failure message, or {@code null} if the request has not failed
   */
  public GetFailedMessage failedMessage() {
    return failedMessage;
  }

  /**
   * Returns the MIME type discovered for the data.
   *
   * <p>The MIME type is a hint derived from request processing and may be {@code null} when not yet
   * known. The value is not normalized or validated by this snapshot.
   *
   * @return the discovered MIME type, or {@code null} if unknown
   */
  public String foundDataMimeType() {
    return foundDataMimeType;
  }

  /**
   * Returns the recorded data length for the request.
   *
   * <p>The length is expressed in bytes and reflects the latest known size at snapshot creation
   * time. A value of {@code 0} may indicate unknown length or a zero-length payload depending on
   * the calling context.
   *
   * @return the recorded data length in bytes
   */
  public long foundDataLength() {
    return foundDataLength;
  }

  /**
   * Returns the destination file for disk-based requests.
   *
   * <p>The file reference is optional and may be {@code null} for in-memory requests or when the
   * destination has not been assigned. The snapshot does not check file existence or permissions.
   *
   * @return the destination file, or {@code null} if not applicable
   */
  public File destinationFile() {
    return destinationFile;
  }

  /**
   * Returns the bucket containing result data.
   *
   * <p>The bucket is optional and may be {@code null} when data is not yet available. No ownership
   * transfer occurs; callers retain responsibility for bucket lifecycle management.
   *
   * @return the result data bucket, or {@code null} if not available
   */
  public Bucket dataBucket() {
    return dataBucket;
  }

  /**
   * Returns the fetch context used for the request.
   *
   * <p>The context can include MIME overrides, filter settings, and other request-scoped options.
   * The snapshot stores the reference as provided and does not copy or validate it.
   *
   * @return the fetch context, or {@code null} if not set
   */
  public FetchContext fetchContext() {
    return fetchContext;
  }

  /**
   * Returns the scheduler priority class for the request.
   *
   * <p>The value is stored verbatim and is interpreted by the request scheduler. This snapshot does
   * not enforce any valid range or normalize the value.
   *
   * @return the priority class as a short value
   */
  public short priorityClass() {
    return priorityClass;
  }

  /**
   * Returns the compatibility modes observed for the request.
   *
   * <p>The returned array is the original reference supplied to the constructor. It may be {@code
   * null} or empty. Callers should treat it as read-only to avoid affecting equality or hash-based
   * collections.
   *
   * @return the compatibility mode array, or {@code null} if not provided
   */
  public CompatibilityMode[] compatModes() {
    return compatModes;
  }

  /**
   * Returns the splitfile crypto key override, if any.
   *
   * <p>The returned array is not copied. It may be {@code null} when no override is configured.
   * Callers should avoid mutating the array after snapshot construction.
   *
   * @return the splitfile key bytes, or {@code null} if no override is set
   */
  public byte[] splitfileKey() {
    return splitfileKey;
  }

  /**
   * Returns the request URI associated with this snapshot.
   *
   * <p>The URI may be {@code null} when the request has not yet resolved a definitive URI or when
   * the caller chooses not to expose it. The snapshot does not validate or normalize it.
   *
   * @return the request URI, or {@code null} if not available
   */
  public FreenetURI uri() {
    return uri;
  }

  /**
   * Indicates whether reinsertion should skip compression.
   *
   * <p>This flag is reported to the status encoder to reflect the caller's reinsertion policy. It
   * does not influence any other values held in this snapshot.
   *
   * @return {@code true} if reinsertion should skip compression, {@code false} otherwise
   */
  public boolean dontCompress() {
    return dontCompress;
  }

  /**
   * Compares this snapshot with another object for value equality.
   *
   * <p>Equality requires all scalar fields to match, as well as array contents for compatibility
   * modes and splitfile key data. Mutable array contents can therefore affect equality over time.
   * This method is deterministic provided the referenced arrays and objects are not mutated while
   * comparison occurs.
   *
   * @param other the object to compare against, possibly {@code null}
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
    return started == otherSnapshot.started
        && finished == otherSnapshot.finished
        && succeeded == otherSnapshot.succeeded
        && foundDataLength == otherSnapshot.foundDataLength
        && priorityClass == otherSnapshot.priorityClass
        && dontCompress == otherSnapshot.dontCompress
        && java.util.Objects.equals(identifier, otherSnapshot.identifier)
        && persistence == otherSnapshot.persistence
        && java.util.Objects.equals(progressPending, otherSnapshot.progressPending)
        && java.util.Objects.equals(failedMessage, otherSnapshot.failedMessage)
        && java.util.Objects.equals(foundDataMimeType, otherSnapshot.foundDataMimeType)
        && java.util.Objects.equals(destinationFile, otherSnapshot.destinationFile)
        && java.util.Objects.equals(dataBucket, otherSnapshot.dataBucket)
        && java.util.Objects.equals(fetchContext, otherSnapshot.fetchContext)
        && Arrays.equals(compatModes, otherSnapshot.compatModes)
        && Arrays.equals(splitfileKey, otherSnapshot.splitfileKey)
        && java.util.Objects.equals(uri, otherSnapshot.uri);
  }

  /**
   * Computes a hash code from all stored snapshot fields.
   *
   * <p>The hash includes the contents of the compatibility mode and splitfile key arrays, making it
   * consistent with {@link #equals(Object)}. Mutating these arrays after construction can change
   * the hash value and should be avoided when the instance is used as a map key.
   *
   * @return a hash code derived from all snapshot fields
   */
  @Override
  public int hashCode() {
    int result =
        java.util.Objects.hash(
            identifier,
            persistence,
            started,
            finished,
            succeeded,
            progressPending,
            failedMessage,
            foundDataMimeType,
            foundDataLength,
            destinationFile,
            dataBucket,
            fetchContext,
            priorityClass,
            uri,
            dontCompress);
    result = 31 * result + Arrays.hashCode(compatModes);
    result = 31 * result + Arrays.hashCode(splitfileKey);
    return result;
  }

  /**
   * Returns a diagnostic string representation of this snapshot.
   *
   * <p>The string includes scalar values and full {@link Arrays#toString(byte[])} output for
   * arrays. Because it may include identifiers and key material, it should be used with care in
   * production logs or user-visible output.
   *
   * @return a human-readable representation of this snapshot
   */
  @Override
  public @NotNull String toString() {
    return "ClientGetStatusSnapshot["
        + "identifier="
        + identifier
        + ", persistence="
        + persistence
        + ", started="
        + started
        + ", finished="
        + finished
        + ", succeeded="
        + succeeded
        + ", progressPending="
        + progressPending
        + ", failedMessage="
        + failedMessage
        + ", foundDataMimeType="
        + foundDataMimeType
        + ", foundDataLength="
        + foundDataLength
        + ", destinationFile="
        + destinationFile
        + ", dataBucket="
        + dataBucket
        + ", fetchContext="
        + fetchContext
        + ", priorityClass="
        + priorityClass
        + ", compatModes="
        + Arrays.toString(compatModes)
        + ", splitfileKey="
        + Arrays.toString(splitfileKey)
        + ", uri="
        + uri
        + ", dontCompress="
        + dontCompress
        + ']';
  }
}

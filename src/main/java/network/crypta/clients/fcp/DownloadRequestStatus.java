package network.crypta.clients.fcp;

import java.io.File;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.InsertContext;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents the mutable life cycle of a single ClientGet request once it has been accepted by the
 * FCP layer. Instances collect success/failure metadata, inferred MIME information, and progressive
 * hints about how the client should treat the retrieved data. The class is designed as a
 * thread-safe hand-off object: request executors update it under synchronization while callers poll
 * immutable snapshots via {@link #copy()} or the exposed read methods.
 *
 * <p>Consumers typically construct an instance when a request enters the queue, pass it through
 * dispatch/execution code, and periodically query it to populate status messages, UI widgets, or
 * persistence payloads. The object keeps track of byte counts, priority, and dynamically discovered
 * insert compatibility modes so that retry logic can make informed decisions about compression and
 * storage layout.
 *
 * <p>Thread-safety is deliberately coarsely grained: most mutators are {@code synchronized} to
 * simplify reasoning over state transitions, while getters expose the most recent consistent view
 * without additional locking. Callers should prefer cloning via {@link #copy()} when they need to
 * hold a reference beyond a single read, because inner arrays (such as split-file keys) are copied
 * defensively.
 *
 * <ul>
 *   <li>Tracks byte size, MIME type, and compression hints for downstream consumers.
 *   <li>Captures both short and long failure reasons for human-readable diagnostics.
 *   <li>Stores redirection targets and split-file metadata so resumed downloads can skip work.
 * </ul>
 *
 * @see RequestStatus
 * @see network.crypta.clients.fcp.ClientGetMessage
 */
public class DownloadRequestStatus extends RequestStatus {
  private static final Logger LOG = LoggerFactory.getLogger(DownloadRequestStatus.class);

  private FetchExceptionMode failureCode;
  private String failureReasonShort;
  private String failureReasonLong;
  // These can be guesses
  private String mimeType;
  private long dataSize;
  // Null = to temp space
  private final File destFilename;
  private CompatibilityMode[] detectedCompatModes;
  private byte[] detectedSplitfileKey;
  private FreenetURI uri;
  boolean filterData;
  Bucket dataShadow;

  /**
   * Indicates whether the caller explicitly requested a MIME override on the returned file. A true
   * value means downstream logic must preserve the supplied MIME type, even when validators report
   * conflicts, whereas false allows detected content types to replace guesses.
   */
  public final boolean overriddenDataType;

  private boolean detectedDontCompress;

  synchronized void setFinished(boolean success, DownloadOutcomeInfo outcome) {
    setFinished(success);
    if (outcome.mimeType() == null
        && (outcome.failureCode() == FetchExceptionMode.CONTENT_VALIDATION_UNKNOWN_MIME
            || outcome.failureCode() == FetchExceptionMode.CONTENT_VALIDATION_BAD_MIME)) {
      logMimeTypeMismatch(outcome.failureCode(), getIdentifier(), uri);
    }
    this.dataSize = outcome.dataSize();
    this.mimeType = outcome.mimeType();
    this.failureCode = outcome.failureCode();
    this.failureReasonLong = outcome.failureReasonLong();
    this.failureReasonShort = outcome.failureReasonShort();
    this.dataShadow = outcome.dataShadow();
    this.filterData = outcome.filterData();
  }

  /**
   * Creates a new download status entry from preassembled snapshots.
   *
   * @param statusSnapshot base request counters and timestamps.
   * @param details download-specific metadata and completion details.
   */
  DownloadRequestStatus(
      RequestStatusSnapshot statusSnapshot, DownloadRequestStatusDetails details) {
    super(statusSnapshot);
    DownloadOutcomeInfo outcome = details.outcome();
    if (outcome.mimeType() == null
        && (outcome.failureCode() == FetchExceptionMode.CONTENT_VALIDATION_UNKNOWN_MIME
            || outcome.failureCode() == FetchExceptionMode.CONTENT_VALIDATION_BAD_MIME)) {
      logMimeTypeMismatch(outcome.failureCode(), statusSnapshot.identifier(), details.uri());
    }
    this.overriddenDataType = details.overriddenDataType();
    this.failureCode = outcome.failureCode();
    this.mimeType = outcome.mimeType();
    this.dataSize = outcome.dataSize();
    this.destFilename = details.destFilename();
    this.detectedCompatModes = details.compatModes();
    this.detectedSplitfileKey = details.splitfileKey();
    this.uri = details.uri();
    this.failureReasonShort = outcome.failureReasonShort();
    this.failureReasonLong = outcome.failureReasonLong();
    this.dataShadow = outcome.dataShadow();
    this.filterData = outcome.filterData();
    this.detectedDontCompress = details.dontCompress();
  }

  private DownloadRequestStatus(DownloadRequestStatus source) {
    super(source);
    this.failureCode = source.failureCode;
    this.failureReasonShort = source.failureReasonShort;
    this.failureReasonLong = source.failureReasonLong;
    this.mimeType = source.mimeType;
    this.dataSize = source.dataSize;
    this.destFilename = source.destFilename;
    this.detectedCompatModes =
        source.detectedCompatModes != null ? source.detectedCompatModes.clone() : null;
    this.detectedSplitfileKey =
        source.detectedSplitfileKey != null ? source.detectedSplitfileKey.clone() : null;
    this.uri = source.uri;
    this.filterData = source.filterData;
    this.dataShadow = source.dataShadow;
    this.overriddenDataType = source.overriddenDataType;
    this.detectedDontCompress = source.detectedDontCompress;
  }

  /**
   * Reports whether the retrieved entity currently targets anonymous temporary storage.
   *
   * <p>When {@code true} the request has no preselected on-disk path; callers should keep the data
   * inside the client area or prompt the user to choose a location. Requests backed by a concrete
   * destination return {@code false} once the destination is known.
   *
   * @return {@code true} when {@link #getDestFilename()} is {@code null}, implying temporary space
   *     usage.
   */
  public final boolean toTempSpace() {
    return destFilename == null;
  }

  /**
   * Provides the most recent fetch failure category reported by the worker thread.
   *
   * <p>The mode helps external logic choose between retries, user-visible explanations, or aborting
   * the transfer entirely. A return value of {@code null} indicates either that the request still
   * runs or that it finished successfully.
   *
   * @return the {@link FetchExceptionMode} describing the last terminal error, or {@code null} when
   *     none has been recorded.
   */
  public FetchExceptionMode getFailureCode() {
    return failureCode;
  }

  /**
   * Returns the MIME type inferred or overridden for the downloaded payload.
   *
   * <p>The method favors explicitly supplied overrides, otherwise falls back to validator-detected
   * values, and may be {@code null} while inference is still pending. Downstream consumers should
   * therefore treat the result as advisory until the request transitions to a finished state and
   * validators confirm whether the MIME was acceptable.
   *
   * @return the MIME type string, or {@code null} when undetermined or still being validated.
   */
  public String getMIMEType() {
    return mimeType;
  }

  /**
   * Reports the best-known size in bytes for the requested payload.
   *
   * <p>The value reflects either the byte count streamed by the network layer, an estimate supplied
   * with the original request, or the length retrieved from metadata. Because status updates are
   * synchronized, callers can treat the number as a consistent snapshot even while the download
   * progresses.
   *
   * @return the byte length advertised so far, or zero when the size has not yet been learned.
   */
  @Override
  public long getDataSize() {
    return dataSize;
  }

  /**
   * Exposes the final destination file requested by the client, when any.
   *
   * <p>This path is only valid on the originating node, must not be shared across trust boundaries,
   * and can be {@code null} while the request is destined for temporary storage or before the user
   * picks a path.
   *
   * @return the destination {@link File}, or {@code null} while targeting temp space.
   */
  public File getDestFilename() {
    return destFilename;
  }

  /**
   * Returns the compatibility modes guessed while parsing the split-file metadata.
   *
   * <p>The returned array may be shared across readers, so callers should copy it if they intend to
   * mutate the contents. The value is {@code null} until compatibility detection runs.
   *
   * @return an array describing the effective {@link CompatibilityMode}s, or {@code null} when
   *     undetected.
   */
  public CompatibilityMode[] getCompatibilityMode() {
    return detectedCompatModes;
  }

  /**
   * Provides the override key used to decrypt split-file blocks when the client supplied one.
   *
   * <p>The array is a snapshot in time; callers should defensively copy it to avoid leaking mutable
   * internals. {@code null} indicates that the request uses the key embedded in the URI itself.
   *
   * @return a byte array holding the override key, or {@code null} when defaulting to the URI key.
   */
  public byte[] getOverriddenSplitfileCryptoKey() {
    return detectedSplitfileKey;
  }

  /**
   * Supplies the URI currently associated with the request, including redirects.
   *
   * <p>The value initially reflects the URI provided by the caller, but the worker may swap in a
   * redirection target once detected via {@link #redirect(FreenetURI)}. Consumers should therefore
   * consult this method each time they need to display or persist linkage data instead of caching
   * an early reference.
   *
   * @return the active {@link FreenetURI} for this download, or {@code null} before initialization.
   */
  @Override
  public FreenetURI getURI() {
    return uri;
  }

  /**
   * Explains why the request failed or was rejected by validation layers.
   *
   * <p>When {@code longDescription} is {@code true}, the method returns the verbose explanation
   * suitable for UI tooltips or logs; otherwise it emits a condensed human-readable summary. Either
   * may be {@code null} if the request has not yet encountered an error or the worker has not
   * filled in the relevant field.
   *
   * @param longDescription {@code true} for the verbose reason, {@code false} for the short label.
   * @return the requested failure reason flavor, or {@code null} when the information is missing.
   */
  @Override
  public synchronized String getFailureReason(boolean longDescription) {
    if (longDescription) return failureReasonLong;
    else return failureReasonShort;
  }

  synchronized void updateDetectedCompatModes(
      InsertContext.CompatibilityMode[] compatModes, boolean dontCompress) {
    this.detectedCompatModes = compatModes;
    this.detectedDontCompress = dontCompress;
  }

  synchronized void updateDetectedSplitfileKey(byte[] splitfileKey) {
    this.detectedSplitfileKey = splitfileKey;
  }

  synchronized void updateExpectedMIME(String foundDataMimeType) {
    this.mimeType = foundDataMimeType;
  }

  synchronized void updateExpectedDataLength(long dataLength) {
    this.dataSize = dataLength;
  }

  /**
   * Exposes the optional bucket that mirrors the download's payload for post-processing.
   *
   * <p>The returned {@link Bucket} is typically a transient shadow used for filtering or checksum
   * verification when the output stream is not directly available to the caller. Because the
   * pointer can change while the download progresses, access is synchronized.
   *
   * @return the current shadow bucket, or {@code null} when no auxiliary copy exists.
   */
  public synchronized Bucket getDataShadow() {
    return dataShadow;
  }

  synchronized void redirect(FreenetURI redirect) {
    this.uri = redirect;
  }

  /**
   * Signals whether the worker discovered that compression should be bypassed for reinsertion.
   *
   * <p>Downloads that carry already compressed or encrypted blocks set this flag so reinsertion
   * logic skips redundant compression attempts. Because the answer can only flip from {@code false}
   * to {@code true}, callers may safely treat a {@code true} value as sticky for the remainder of
   * the job.
   *
   * @return {@code true} when compression should be avoided, {@code false} otherwise.
   */
  public synchronized boolean detectedDontCompress() {
    return detectedDontCompress;
  }

  /**
   * Provides the filename clients should display when offering a save dialog or progress entry.
   *
   * <p>The destination filename takes precedence when explicitly provided. Otherwise, the method
   * derives a name from {@link FreenetURI#getPreferredFilename()} provided the URI supplies
   * meta-strings or a document name. {@code null} is returned when no reasonable candidate exists.
   *
   * @return a display-ready filename suggestion, or {@code null} when unavailable.
   */
  @Override
  public String getPreferredFilename() {
    if (destFilename != null) return destFilename.getName();
    if (uri != null && (uri.hasMetaStrings() || uri.getDocName() != null))
      return uri.getPreferredFilename();
    return null;
  }

  /**
   * Creates a defensive snapshot of this status object, including copies of mutable arrays.
   *
   * <p>The returned instance is detached from future updates, making it safe to cache or publish
   * beyond the owning thread. Use this when serializing status responses or when UI components need
   * to observe a stable view while the background task keeps running.
   *
   * @return an immutable snapshot of the current status fields.
   */
  @Override
  public DownloadRequestStatus copy() {
    return new DownloadRequestStatus(this);
  }

  private static void logMimeTypeMismatch(
      FetchExceptionMode failureCode, String identifier, FreenetURI uri) {
    if (!LOG.isErrorEnabled()) {
      return;
    }
    LOG.error(
        "MIME type is null but failure code is {} for {} : {}",
        FetchException.getMessage(failureCode),
        identifier,
        uri,
        new Exception("error"));
  }
}

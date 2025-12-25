package network.crypta.client;

import java.io.Serial;
import java.util.HashMap;
import network.crypta.client.filter.DataFilterException;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Thrown when a high‑level content fetch fails.
 *
 * <p>This exception transports rich failure information from the network and client stack to
 * callers and user interfaces. Besides the {@linkplain #mode error mode}, instances may carry a
 * replacement {@linkplain #newURI URI} to try, an {@linkplain #getExpectedSize() expected size}, a
 * declared or inferred MIME type, and whether size/MIME are considered finalized. The class also
 * exposes helpers that answer common questions such as whether a failure is retryable (see {@link
 * #isFatal()}) and whether any data was found (see {@link #isDataFound()}).
 *
 * <p>Typical call patterns:
 *
 * <ul>
 *   <li>Network code constructs a {@code FetchException} when a request cannot progress or should
 *       stop, optionally attaching the underlying {@linkplain #getCause() cause} (for example a
 *       content‑filter exception).
 *   <li>Higher layers inspect {@link #mode}, {@link #getCause()}, and helpers such as {@link
 *       #isFatal()} to decide between retry, redirect, or user‑visible error.
 *   <li>UI components render a concise message via {@link #getShortMessage()} and include details
 *       such as expected size and MIME if present.
 * </ul>
 *
 * <p>Immutability and thread‑safety: Public fields and accessors expose read‑only state that is set
 * at construction. Helpers like {@link #withExpectedSize(long)} and {@link #notFinalized()} create
 * defensive copies rather than mutating existing instances. Instances are safe to pass between
 * threads for read‑only use.
 *
 * <p>Design notes: For most failure modes (except {@link FetchExceptionMode#INTERNAL_ERROR}) stack
 * traces are rarely useful, so the message and error mode are the primary contract. The direct
 * {@linkplain #getCause() cause} is preserved when cloning to allow downstream components to detect
 * and specialize on underlying exceptions.
 */
public class FetchException extends Exception {
  private static final Logger LOG = LoggerFactory.getLogger(FetchException.class);
  private static final String LOG_INTERNAL_ERROR = "Internal error";
  private static final String LOG_DEBUG_PATTERN = "FetchException({})";

  @Serial private static final long serialVersionUID = -1106716067841151962L;

  /** Failure mode */
  public final FetchExceptionMode mode;

  /**
   * Try this URI instead. If we fetch a USK and there is a more recent version, for example, we
   * will get a FetchException, but it will give a new URI to try so we can update our links,
   * bookmarks, or convert it to an HTTP Permanent Redirect.
   */
  public final FreenetURI newURI;

  /**
   * The expected size of the data had the fetch succeeded, or -1. May not be accurate. If retrying
   * after TOO_BIG, you need to set the temporary and final data limits to at least this big!
   */
  private final long expectedSize;

  /** The expected final MIME type, or null. */
  final String expectedMimeType;

  /** If true, the expected MIME type and size are probably accurate. */
  final boolean finalizedSizeAndMimeType;

  /**
   * Returns the expected MIME type of the data, if known.
   *
   * @return the MIME type string such as {@code text/html}, or {@code null} when unknown
   */
  public String getExpectedMimeType() {
    return expectedMimeType;
  }

  /**
   * Indicates whether the size and MIME type are likely final.
   *
   * <p>When this method returns {@code true}, callers can treat {@link #getExpectedSize()} and
   * {@link #getExpectedMimeType()} as authoritative best‑effort values for error reporting and
   * follow‑up actions. When {@code false}, these values are provisional and may change if the
   * request were to continue.
   *
   * @return {@code true} when size/MIME are finalized; {@code false} when provisional
   */
  public boolean finalizedSize() {
    return finalizedSizeAndMimeType;
  }

  /**
   * Returns the expected size of the content, or {@code -1} if unknown.
   *
   * <p>This value may be a best‑effort estimate provided by the network and is not always final
   * unless {@link #finalizedSize()} returns {@code true}.
   *
   * @return content length in bytes or {@code -1} when the size is unknown
   */
  public long getExpectedSize() {
    return expectedSize;
  }

  /**
   * Returns a new {@code FetchException} with the provided expected size.
   *
   * <p>The returned instance preserves the original {@linkplain #mode error mode}, message, new
   * URI, error codes, and the direct {@linkplain #getCause() cause}. Only size/finalization/MIME
   * fields may differ according to the arguments supplied.
   *
   * @param newExpectedSize the size in bytes to record for this failure; use {@code -1} when
   *     unknown
   * @return a copy of this exception that reports {@code newExpectedSize}
   */
  public FetchException withExpectedSize(long newExpectedSize) {
    return new FetchException(
        this, newExpectedSize, this.finalizedSizeAndMimeType, this.expectedMimeType);
  }

  /**
   * If there are many failures, usually in a splitfile fetch, tracks the number of failures of each
   * type.
   */
  public final FailureCodeTracker errorCodes;

  /** Extra information about the failure. */
  public final String extraMessage;

  /**
   * Returns the structured error mode describing why the fetch failed.
   *
   * <p>Use with {@link #isFatal(FetchExceptionMode)} and {@link #isDataFound(FetchExceptionMode,
   * FailureCodeTracker)} to derive high‑level behavior such as retry-ability or whether any data
   * was found.
   *
   * @return non‑null error mode associated with this failure
   */
  public FetchExceptionMode getMode() {
    return mode;
  }

  /**
   * Creates a failure with the given error mode and no additional context.
   *
   * <p>Use this when only the {@link FetchExceptionMode} is known. Size/MIME are set to unknown,
   * there is no redirect URI, and no error code breakdown.
   *
   * @param m the error mode explaining why the fetch failed; must not be {@code null}
   */
  public FetchException(FetchExceptionMode m) {
    super(getMessage(m));
    extraMessage = null;
    mode = m;
    errorCodes = null;
    newURI = null;
    expectedSize = -1;
    expectedMimeType = null;
    finalizedSizeAndMimeType = false;
    if (mode == FetchExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a failure with an expected size and optional MIME type.
   *
   * @param m the error mode; must not be {@code null}
   * @param expectedSize the estimated or final size in bytes, or {@code -1} when unknown
   * @param finalizedSize whether {@code expectedSize} and {@code expectedMimeType} are considered
   *     final (authoritative)
   * @param expectedMimeType the MIME type if known, otherwise {@code null}
   */
  public FetchException(
      FetchExceptionMode m, long expectedSize, boolean finalizedSize, String expectedMimeType) {
    super(getMessage(m));
    extraMessage = null;
    this.finalizedSizeAndMimeType = finalizedSize;
    mode = m;
    errorCodes = null;
    newURI = null;
    this.expectedSize = expectedSize;
    this.expectedMimeType = expectedMimeType;
    if (mode == FetchExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a failure with size, MIME, and a replacement URI to try.
   *
   * @param m the error mode; must not be {@code null}
   * @param expectedSize the estimated or final size in bytes, or {@code -1} when unknown
   * @param finalizedSize whether {@code expectedSize} and {@code expectedMimeType} are considered
   *     final (authoritative)
   * @param expectedMimeType the MIME type if known, otherwise {@code null}
   * @param uri a new URI that callers may try instead; may be {@code null}
   */
  public FetchException(
      FetchExceptionMode m,
      long expectedSize,
      boolean finalizedSize,
      String expectedMimeType,
      FreenetURI uri) {
    super(getMessage(m));
    extraMessage = null;
    this.finalizedSizeAndMimeType = finalizedSize;
    mode = m;
    errorCodes = null;
    newURI = uri;
    this.expectedSize = expectedSize;
    this.expectedMimeType = expectedMimeType;
    if (mode == FetchExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a failure from a metadata parsing error.
   *
   * @param e the parsing exception that triggered the failure; used as the cause and for the
   *     message
   */
  public FetchException(MetadataParseException e) {
    super(getMessage(FetchExceptionMode.INVALID_METADATA) + ": " + e.getMessage());
    extraMessage = e.getMessage();
    mode = FetchExceptionMode.INVALID_METADATA;
    errorCodes = null;
    initCause(e);
    newURI = null;
    expectedSize = -1;
    expectedMimeType = null;
    finalizedSizeAndMimeType = false;
    if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a failure from an archive processing error.
   *
   * @param e the archive processing exception; becomes the direct cause and contributes to the
   *     message
   */
  public FetchException(ArchiveFailureException e) {
    super(getMessage(FetchExceptionMode.ARCHIVE_FAILURE) + ": " + e.getMessage());
    extraMessage = e.getMessage();
    mode = FetchExceptionMode.ARCHIVE_FAILURE;
    errorCodes = null;
    newURI = null;
    initCause(e);
    expectedSize = -1;
    expectedMimeType = null;
    finalizedSizeAndMimeType = false;
    if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a failure representing an archive restart condition.
   *
   * @param e the restart exception signaling that an archive operation should be restarted; becomes
   *     the direct cause
   */
  public FetchException(ArchiveRestartException e) {
    super(getMessage(FetchExceptionMode.ARCHIVE_RESTART) + ": " + e.getMessage());
    extraMessage = e.getMessage();
    mode = FetchExceptionMode.ARCHIVE_FAILURE;
    errorCodes = null;
    initCause(e);
    newURI = null;
    expectedSize = -1;
    expectedMimeType = null;
    finalizedSizeAndMimeType = false;
    if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a failure with an explicit cause.
   *
   * @param mode the error mode; must not be {@code null}
   * @param t the underlying cause; used for the message and as {@linkplain #getCause() cause}
   */
  public FetchException(FetchExceptionMode mode, Throwable t) {
    super(getMessage(mode) + ": " + t.getMessage());
    extraMessage = t.getMessage();
    this.mode = mode;
    errorCodes = null;
    initCause(t);
    newURI = null;
    expectedSize = -1;
    expectedMimeType = null;
    finalizedSizeAndMimeType = false;
    if (mode == FetchExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a failure with a caller‑supplied reason and cause.
   *
   * @param mode the error mode; must not be {@code null}
   * @param reason additional context to prefix in the message; should be concise and user‑friendly
   * @param t the underlying cause; used for the message and as {@linkplain #getCause() cause}
   */
  public FetchException(FetchExceptionMode mode, String reason, Throwable t) {
    super(reason + " : " + getMessage(mode) + ": " + t.getMessage());
    extraMessage = t.getMessage();
    this.mode = mode;
    errorCodes = null;
    initCause(t);
    newURI = null;
    expectedSize = -1;
    expectedMimeType = null;
    finalizedSizeAndMimeType = false;
    if (mode == FetchExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a failure with expected size, reason, cause, and MIME type.
   *
   * @param mode the error mode; must not be {@code null}
   * @param expectedSize estimated or final size in bytes, or {@code -1} when unknown
   * @param reason additional context to include in the message
   * @param t the underlying cause; becomes the direct cause
   * @param expectedMimeType MIME type to report alongside the failure, or {@code null}
   */
  public FetchException(
      FetchExceptionMode mode,
      long expectedSize,
      String reason,
      Throwable t,
      String expectedMimeType) {
    super(reason + " : " + getMessage(mode) + ": " + t.getMessage());
    extraMessage = t.getMessage();
    this.mode = mode;
    this.expectedSize = expectedSize;
    this.expectedMimeType = expectedMimeType;
    this.finalizedSizeAndMimeType = false;
    errorCodes = null;
    initCause(t);
    newURI = null;
    if (mode == FetchExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a failure for content that failed validation in the content filter.
   *
   * @param expectedSize estimated or final size in bytes, or {@code -1} when unknown
   * @param t the filter‑level exception describing why the content is unsafe; becomes the direct
   *     cause
   * @param expectedMimeType MIME type inferred or declared for the content; may be {@code null}
   */
  public FetchException(long expectedSize, DataFilterException t, String expectedMimeType) {
    super(
        getMessage(FetchExceptionMode.CONTENT_VALIDATION_FAILED)
            + " "
            + NodeL10n.getBase().getString("FetchException.unsafeContentDetails")
            + " "
            + t.getMessage());
    extraMessage = t.getMessage();
    this.mode = FetchExceptionMode.CONTENT_VALIDATION_FAILED;
    this.expectedSize = expectedSize;
    this.expectedMimeType = expectedMimeType;
    this.finalizedSizeAndMimeType = false;
    errorCodes = null;
    initCause(t);
    newURI = null;
    if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a failure with expected size, cause, and MIME type.
   *
   * @param mode the error mode; must not be {@code null}
   * @param expectedSize estimated or final size in bytes, or {@code -1} when unknown
   * @param t the underlying cause; becomes the direct cause
   * @param expectedMimeType MIME type to report alongside the failure, or {@code null}
   */
  public FetchException(
      FetchExceptionMode mode, long expectedSize, Throwable t, String expectedMimeType) {
    super(getMessage(mode) + ": " + t.getMessage());
    extraMessage = t.getMessage();
    this.mode = mode;
    this.expectedSize = expectedSize;
    this.expectedMimeType = expectedMimeType;
    this.finalizedSizeAndMimeType = false;
    errorCodes = null;
    initCause(t);
    newURI = null;
    if (mode == FetchExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a failure aggregating low‑level error codes.
   *
   * @param mode the error mode; must not be {@code null}
   * @param errorCodes a non‑empty tracker summarizing underlying failures; may be cloned internally
   */
  public FetchException(FetchExceptionMode mode, FailureCodeTracker errorCodes) {
    super(getMessage(mode));
    if (errorCodes.isEmpty()) {
      LOG.error("Failing with no error codes?!");
    }
    extraMessage = null;
    this.mode = mode;
    this.errorCodes = errorCodes;
    newURI = null;
    expectedSize = -1;
    expectedMimeType = null;
    finalizedSizeAndMimeType = false;
    if (mode == FetchExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a failure aggregating low‑level error codes with an additional message.
   *
   * @param mode the error mode; must not be {@code null}
   * @param errorCodes a non‑empty tracker summarizing underlying failures; may be cloned internally
   * @param msg additional human‑readable context included in the message
   */
  public FetchException(FetchExceptionMode mode, FailureCodeTracker errorCodes, String msg) {
    super(getMessage(mode) + ": " + msg);
    if (errorCodes.isEmpty()) {
      LOG.error("Failing with no error codes?!");
    }
    extraMessage = msg;
    this.mode = mode;
    this.errorCodes = errorCodes;
    newURI = null;
    expectedSize = -1;
    expectedMimeType = null;
    finalizedSizeAndMimeType = false;
    if (mode == FetchExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a failure with the given error mode and message.
   *
   * @param mode the error mode; must not be {@code null}
   * @param msg additional context to append to the standard message for {@code mode}
   */
  public FetchException(FetchExceptionMode mode, String msg) {
    super(getMessage(mode) + ": " + msg);
    extraMessage = msg;
    errorCodes = null;
    this.mode = mode;
    newURI = null;
    expectedSize = -1;
    expectedMimeType = null;
    finalizedSizeAndMimeType = false;
    if (mode == FetchExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a failure that also supplies an alternative URI to try.
   *
   * @param mode the error mode; must not be {@code null}
   * @param newURI redirect/alternate URI that callers may try instead; may be {@code null}
   */
  public FetchException(FetchExceptionMode mode, FreenetURI newURI) {
    super(getMessage(mode));
    extraMessage = null;
    this.mode = mode;
    errorCodes = null;
    this.newURI = newURI;
    expectedSize = -1;
    expectedMimeType = null;
    finalizedSizeAndMimeType = false;
    if (mode == FetchExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a failure with a message and a replacement URI.
   *
   * @param mode the error mode; must not be {@code null}
   * @param msg additional context to append to the standard message for {@code mode}
   * @param uri redirect/alternate URI that callers may try instead; may be {@code null}
   */
  public FetchException(FetchExceptionMode mode, String msg, FreenetURI uri) {
    super(getMessage(mode) + ": " + msg);
    extraMessage = msg;
    errorCodes = null;
    this.mode = mode;
    newURI = uri;
    expectedSize = -1;
    expectedMimeType = null;
    finalizedSizeAndMimeType = false;
    if (mode == FetchExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a copy of another {@code FetchException} with a different error mode.
   *
   * <p>Metadata such as expected size, MIME, URI, and message are propagated.
   *
   * @param e the source exception to copy; must not be {@code null}
   * @param newMode the error mode for the returned exception; must not be {@code null}
   */
  public FetchException(FetchException e, FetchExceptionMode newMode) {
    super(getMessage(newMode) + (e.extraMessage != null ? ": " + e.extraMessage : ""));
    this.mode = newMode;
    this.newURI = e.newURI;
    this.errorCodes = e.errorCodes;
    this.expectedMimeType = e.expectedMimeType;
    this.expectedSize = e.getExpectedSize();
    this.extraMessage = e.extraMessage;
    this.finalizedSizeAndMimeType = e.finalizedSizeAndMimeType;
    if (mode == FetchExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a copy of another {@code FetchException} with a different redirect URI.
   *
   * <p>The original direct cause (if any) is preserved.
   *
   * @param e the source exception to copy; must not be {@code null}
   * @param uri new URI to embed; may be {@code null}
   */
  public FetchException(FetchException e, FreenetURI uri) {
    super(e.getMessage());
    if (e.getCause() != null) initCause(e.getCause());
    this.mode = e.mode;
    this.newURI = uri;
    this.errorCodes = e.errorCodes;
    this.expectedMimeType = e.expectedMimeType;
    this.expectedSize = e.getExpectedSize();
    this.extraMessage = e.extraMessage;
    this.finalizedSizeAndMimeType = e.finalizedSizeAndMimeType;
    if (mode == FetchExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * Creates a shallow copy of another {@code FetchException}.
   *
   * <p>The message and direct cause are preserved; error codes are defensively cloned when present.
   *
   * @param e the source exception to copy; must not be {@code null}
   */
  public FetchException(FetchException e) {
    super(e.getMessage());
    initCause(e);
    this.mode = e.mode;
    this.newURI = e.newURI;
    this.errorCodes = FailureCodeTracker.copyOf(e.errorCodes);
    this.expectedMimeType = e.expectedMimeType;
    this.expectedSize = e.getExpectedSize();
    this.extraMessage = e.extraMessage;
    this.finalizedSizeAndMimeType = e.finalizedSizeAndMimeType;
    if (mode == FetchExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_DEBUG_PATTERN, getMessage(mode), this);
  }

  /**
   * No‑arg constructor for serialization frameworks.
   *
   * <p>State is initialized to neutral values and should be populated by the deserialization
   * mechanism. Application code should not call this constructor directly.
   */
  protected FetchException() {
    // For serialization.
    mode = null;
    newURI = null;
    errorCodes = null;
    extraMessage = null;
    expectedSize = -1;
    expectedMimeType = null;
    finalizedSizeAndMimeType = false;
  }

  /**
   * Returns a concise description of the failure.
   *
   * <p>When a cause is present, the cause’s {@code toString()} is returned to aid specialized error
   * views (e.g., content filter messages). Otherwise, a localized short label for the current
   * {@link #mode} is returned.
   *
   * @return short, user‑visible string describing the failure
   */
  public String getShortMessage() {
    if (getCause() != null) return getCause().toString();
    return (mode != null) ? getShortMessage(mode) : "Unknown code null";
  }

  /**
   * Returns the localized short label for the provided error mode.
   *
   * @param mode the error mode for which a short message is requested; must not be {@code null}
   * @return a brief, localized label; never {@code null}, but may fall back to a generic string
   */
  public static String getShortMessage(FetchExceptionMode mode) {
    // Note: localization keys currently use numeric codes rather than names
    int code = mode.code;
    String ret = NodeL10n.getBase().getString("FetchException.shortError." + code);
    if (ret == null || ret.isEmpty()) return "Unknown code " + mode;
    else return ret;
  }

  @Override
  public String toString() {
    return "FetchException:"
        + (mode != null ? getMessage(mode) : "null")
        + ':'
        + newURI
        + ':'
        + expectedSize
        + ':'
        + expectedMimeType
        + ':'
        + finalizedSizeAndMimeType
        + ':'
        + errorCodes
        + ':'
        + extraMessage;
  }

  /**
   * Returns a concise, user‑friendly message for display.
   *
   * <p>When {@link #extraMessage} is present it is appended to the short message.
   *
   * @return a compact message suitable for UI presentation
   */
  public String toUserFriendlyString() {
    if (extraMessage == null) return getShortMessage(mode);
    else return getShortMessage(mode) + " : " + extraMessage;
  }

  /**
   * Returns the localized long explanation for the provided error mode.
   *
   * @param mode the error mode to describe; must not be {@code null}
   * @return a localized string explaining the failure mode; never {@code null}
   */
  public static String getMessage(FetchExceptionMode mode) {
    if (mode == null) throw new NullPointerException();
    int code = mode.code;
    // Note: localization keys currently use numeric codes rather than names
    String ret = NodeL10n.getBase().getString("FetchException.longError." + code);
    if (ret == null) return "Unknown fetch error code: " + mode;
    else return ret;
  }

  private static final HashMap<Integer, FetchExceptionMode> modes = new HashMap<>();

  // Modes should stay the same even if we remove some elements.
  /**
   * Enumerates the stable set of fetch failure modes.
   *
   * <p>Each constant has a stable {@link #code} used in localization keys and persisted data.
   */
  public enum FetchExceptionMode {

    // Note: many of these are not used anymore

    /** Too many levels of recursion into archives */
    @Deprecated // not used
    TOO_DEEP_ARCHIVE_RECURSION(1),
    /** Don't know what to do with splitfile */
    @Deprecated // not used
    UNKNOWN_SPLITFILE_METADATA(2),
    /** Don't know what to do with metadata */
    UNKNOWN_METADATA(3),
    /** Got a MetadataParseException */
    INVALID_METADATA(4),
    /** Got an ArchiveFailureException */
    ARCHIVE_FAILURE(5),
    /** Failed to decode a block. But we found it i.e. it is valid on the network level. */
    BLOCK_DECODE_ERROR(6),
    /** Too many split metadata levels */
    @Deprecated // not used
    TOO_MANY_METADATA_LEVELS(7),
    /** Too many archive restarts */
    TOO_MANY_ARCHIVE_RESTARTS(8),
    /** Too deep recursion */
    // Note: some TOO_MUCH_RECURSION may be TOO_DEEP_ARCHIVE_RECURSION
    TOO_MUCH_RECURSION(9),
    /** Tried to access an archive file but not in an archive */
    NOT_IN_ARCHIVE(10),
    /**
     * Too many meta strings. E.g. requesting CHK@blah,blah,blah as CHK@blah,blah,blah/filename.ext
     */
    TOO_MANY_PATH_COMPONENTS(11),
    /** Failed to read from or write to a bucket; a kind of internal error */
    BUCKET_ERROR(12),
    /** Data not found */
    DATA_NOT_FOUND(13),
    /** Route not found */
    ROUTE_NOT_FOUND(14),
    /** Downstream overload */
    REJECTED_OVERLOAD(15),
    /** Too many redirects */
    @Deprecated // not used
    TOO_MANY_REDIRECTS(16),
    /** An internal error occurred */
    INTERNAL_ERROR(17),
    /** The node found the data but the transfer failed */
    TRANSFER_FAILED(18),
    /** Splitfile error. This should be a SplitFetchException. */
    SPLITFILE_ERROR(19),
    /** Invalid URI. */
    INVALID_URI(20),
    /** Too big */
    TOO_BIG(21),
    /** Metadata too big */
    TOO_BIG_METADATA(22),
    /** Splitfile has too big segments */
    TOO_MANY_BLOCKS_PER_SEGMENT(23),
    /** Not enough meta strings in URI given and no default document */
    NOT_ENOUGH_PATH_COMPONENTS(24),
    /** Explicitly canceled */
    CANCELLED(25),
    /** Archive restart */
    ARCHIVE_RESTART(26),
    /** There is a more recent version of the USK, ~= HTTP 301; FProxy will turn this into a 301 */
    PERMANENT_REDIRECT(27),
    /** Not all data was found; some DNFs but some successes */
    ALL_DATA_NOT_FOUND(28),
    /** Requestor specified a list of allowed MIME types, and the key's type wasn't in the list */
    WRONG_MIME_TYPE(29),
    /** A node killed the request because it had recently been tried and had DNFed */
    RECENTLY_FAILED(30),
    /** Content filtration has generally failed to produce clean data */
    CONTENT_VALIDATION_FAILED(31),
    /** The content filter does not recognize this data type */
    CONTENT_VALIDATION_UNKNOWN_MIME(32),
    /** The content filter knows this data type is dangerous */
    CONTENT_VALIDATION_BAD_MIME(33),
    /** The metadata specified a hash but the data didn't match it. */
    CONTENT_HASH_FAILED(34),
    /** FEC decode produced a block that doesn't match the data in the original splitfile. */
    SPLITFILE_DECODE_ERROR(35),
    /**
     * For a filtered download to disk, the MIME type is incompatible with the extension,
     * potentially resulting in data on disk filtered with one MIME type but accessed by the
     * operating system with another MIME type. This is equivalent to it not being filtered at all
     * i.e. potentially dangerous.
     */
    MIME_INCOMPATIBLE_WITH_EXTENSION(36),
    /** Not enough disk space to start a download or the next stage of a download. */
    NOT_ENOUGH_DISK_SPACE(37);

    /**
     * Stable numeric code used for localization keys and persisted representations.
     *
     * <p>Codes are unique and must remain stable across versions. Call {@link #getByCode(int)} to
     * map a code back to an enum constant.
     */
    public final int code;

    FetchExceptionMode(int code) {
      this.code = code;
      if (code < 0 || code >= UPPER_LIMIT_ERROR_CODE) throw new IllegalArgumentException();
      if (modes.containsKey(code)) throw new IllegalArgumentException();
      modes.put(code, this);
      // MAX_ERROR_CODE is computed statically from declared modes.
    }

    /**
     * Returns the failure mode associated with the given stable numeric code.
     *
     * @param code a valid {@linkplain #code stable code} previously emitted by this enum
     * @return the corresponding enum constant; never {@code null}
     * @throws IllegalArgumentException if {@code code} does not map to a known constant
     */
    public static FetchExceptionMode getByCode(int code) {
      if (modes.get(code) == null) throw new IllegalArgumentException();
      return modes.get(code);
    }
  }

  private static final int MAX_ERROR_CODE = 37;

  /**
   * There will never be more error codes than this constant. Must not change, used for some data
   * structures.
   */
  public static final int UPPER_LIMIT_ERROR_CODE = 1024;

  /**
   * Returns whether this failure is considered fatal (not worth retrying).
   *
   * @return {@code true} when retrying is not expected to help; {@code false} otherwise
   */
  public boolean isFatal() {
    return isFatal(mode);
  }

  /**
   * Returns whether the supplied failure mode is considered fatal (not worth retrying).
   *
   * @param mode the error mode to evaluate; must not be {@code null}
   * @return {@code true} when retrying is not expected to help; {@code false} otherwise
   */
  public static boolean isFatal(FetchExceptionMode mode) {
    if (isDeprecatedMode(mode)) {
      return true;
    }
    return switch (mode) {
      // Problems with the data as inserted, or the URI given. No point retrying.
      case ARCHIVE_FAILURE,
          BLOCK_DECODE_ERROR,
          TOO_MANY_PATH_COMPONENTS,
          NOT_ENOUGH_PATH_COMPONENTS,
          INVALID_METADATA,
          NOT_IN_ARCHIVE,
          TOO_MANY_ARCHIVE_RESTARTS,
          TOO_MUCH_RECURSION,
          UNKNOWN_METADATA,
          INVALID_URI,
          TOO_BIG,
          TOO_BIG_METADATA,
          TOO_MANY_BLOCKS_PER_SEGMENT,
          CONTENT_HASH_FAILED,
          SPLITFILE_DECODE_ERROR ->
          true;

      // Low level errors, can be retried. Not usually fatal.
      case DATA_NOT_FOUND,
          ROUTE_NOT_FOUND,
          REJECTED_OVERLOAD,
          TRANSFER_FAILED,
          ALL_DATA_NOT_FOUND,
          RECENTLY_FAILED, // wait a bit, but fine
          SPLITFILE_ERROR ->
          false;
      case BUCKET_ERROR, INTERNAL_ERROR, NOT_ENOUGH_DISK_SPACE ->
          // No point retrying.
          true;

      // The ContentFilter failed to validate the data. Retrying won't fix this.
      case CONTENT_VALIDATION_FAILED,
          CONTENT_VALIDATION_UNKNOWN_MIME,
          CONTENT_VALIDATION_BAD_MIME,
          MIME_INCOMPATIBLE_WITH_EXTENSION ->
          true;

      // Weird ones
      case CANCELLED ->
          // Treat user-initiated cancellations as non-fatal so callers may
          // retry or ignore without backoff semantics.
          false;
      case ARCHIVE_RESTART, PERMANENT_REDIRECT, WRONG_MIME_TYPE ->
          // Fatal
          true;
      default -> throw new IllegalStateException("Unhandled mode: " + mode);
    };
  }

  /**
   * Returns whether this failure is definitively fatal for the inserted data itself.
   *
   * <p>Unlike {@link #isFatal()}, a non‑fatal return value here does not imply that retrying would
   * succeed; it only distinguishes environmental issues from problems intrinsic to the data.
   *
   * @return {@code true} when the failure conclusively indicates a problem with the data
   */
  public boolean isDefinitelyFatal() {
    return isDefinitelyFatal(mode);
  }

  /**
   * Returns whether the supplied failure mode is definitively fatal for the inserted data.
   *
   * @param mode the error mode to evaluate; must not be {@code null}
   * @return {@code true} when the failure conclusively indicates a problem with the data
   */
  public static boolean isDefinitelyFatal(FetchExceptionMode mode) {
    if (isDeprecatedMode(mode)) {
      return true;
    }
    return switch (mode) {
      // Problems with the data as inserted, or the URI given. No point retrying.
      case ARCHIVE_FAILURE,
          BLOCK_DECODE_ERROR,
          TOO_MANY_PATH_COMPONENTS,
          NOT_ENOUGH_PATH_COMPONENTS,
          INVALID_METADATA,
          NOT_IN_ARCHIVE,
          TOO_MANY_ARCHIVE_RESTARTS,
          TOO_MUCH_RECURSION,
          UNKNOWN_METADATA,
          INVALID_URI,
          TOO_BIG,
          TOO_BIG_METADATA,
          TOO_MANY_BLOCKS_PER_SEGMENT,
          CONTENT_HASH_FAILED,
          SPLITFILE_DECODE_ERROR ->
          true;

      // Low level errors, can be retried. Not usually fatal.
      case DATA_NOT_FOUND,
          ROUTE_NOT_FOUND,
          REJECTED_OVERLOAD,
          TRANSFER_FAILED,
          ALL_DATA_NOT_FOUND,
          RECENTLY_FAILED, // wait a bit, but fine
          SPLITFILE_ERROR ->
          false;
      case BUCKET_ERROR, INTERNAL_ERROR, NOT_ENOUGH_DISK_SPACE ->
          // No point retrying.
          // But it's not really fatal. I.e. it's not necessarily a problem with the inserted data.
          false;

      // The ContentFilter failed to validate the data. Retrying won't fix this.
      case CONTENT_VALIDATION_FAILED,
          CONTENT_VALIDATION_UNKNOWN_MIME,
          CONTENT_VALIDATION_BAD_MIME,
          MIME_INCOMPATIBLE_WITH_EXTENSION ->
          true;

      // Wierd ones
      // Not necessarily a problem with the inserted data.
      case CANCELLED -> false;
      case ARCHIVE_RESTART, PERMANENT_REDIRECT, WRONG_MIME_TYPE ->
          // Fatal
          true;
      default -> throw new IllegalStateException("Unhandled mode: " + mode);
    };
  }

  /**
   * Returns whether any data was found even though the fetch failed.
   *
   * @return {@code true} when some data was located (e.g., wrong MIME, too big, etc.)
   */
  public boolean isDataFound() {
    return isDataFound(mode, errorCodes);
  }

  /**
   * Returns whether any data was found given the supplied mode and error code summary.
   *
   * @param mode the error mode to evaluate; must not be {@code null}
   * @param errorCodes optional tracker with low‑level errors for split‑file cases; may be {@code
   *     null}
   * @return {@code true} when some data was located for the failure scenario
   */
  public static boolean isDataFound(FetchExceptionMode mode, FailureCodeTracker errorCodes) {
    if (isDeprecatedMode(mode)) {
      return true;
    }
    return switch (mode) {
      case UNKNOWN_METADATA,
          INVALID_METADATA,
          ARCHIVE_FAILURE,
          BLOCK_DECODE_ERROR,
          TOO_MANY_ARCHIVE_RESTARTS,
          TOO_MUCH_RECURSION,
          NOT_IN_ARCHIVE,
          TOO_MANY_PATH_COMPONENTS,
          TOO_BIG,
          TOO_BIG_METADATA,
          TOO_MANY_BLOCKS_PER_SEGMENT,
          NOT_ENOUGH_PATH_COMPONENTS,
          ARCHIVE_RESTART,
          CONTENT_VALIDATION_FAILED,
          CONTENT_VALIDATION_UNKNOWN_MIME,
          CONTENT_VALIDATION_BAD_MIME,
          CONTENT_HASH_FAILED,
          SPLITFILE_DECODE_ERROR,
          NOT_ENOUGH_DISK_SPACE ->
          true;
      case SPLITFILE_ERROR -> errorCodes != null && errorCodes.isDataFound();
      default -> false;
    };
  }

  /**
   * Returns whether the supplied mode corresponds to a deprecated stable error code.
   *
   * <p>Deprecated modes remain in the enum for compatibility, but callers should avoid referencing
   * those constants directly.
   */
  private static boolean isDeprecatedMode(FetchExceptionMode mode) {
    int code = mode.code;
    return code == 1 || code == 2 || code == 7 || code == 16;
  }

  /**
   * Returns whether this failure is “data not found” (DNF) or a recent equivalent.
   *
   * @return {@code true} for DNF‐style modes; {@code false} otherwise
   */
  public boolean isDNF() {
    return switch (mode) {
      case DATA_NOT_FOUND, ALL_DATA_NOT_FOUND, RECENTLY_FAILED -> true;
      default -> false;
    };
  }

  /**
   * Returns whether the given numeric value is a recognized error code.
   *
   * @param code the numeric code to validate
   * @return {@code true} when {@code code} is within the declared range of error codes
   */
  public static boolean isErrorCode(int code) {
    return code >= 0 && code <= MAX_ERROR_CODE;
  }

  /**
   * Returns a copy of this exception with the “finalized” flag cleared.
   *
   * @return a new instance identical to this one except that {@link #finalizedSize()} is {@code
   *     false}
   */
  public FetchException notFinalized() {
    return new FetchException(this, this.expectedSize, false, this.expectedMimeType);
  }

  /** Internal copy constructor that allows overriding selected immutable fields. */
  private FetchException(
      FetchException base, long expectedSize, boolean finalized, String expectedMimeType) {
    super(base.getMessage());
    // Preserve the original underlying cause rather than chaining through the
    // intermediate FetchException copy. Many callers (e.g., UI toadlets) inspect
    // the direct cause to detect specific errors such as UnsafeContentTypeException.
    Throwable cause = base.getCause();
    if (cause != null) initCause(cause);
    this.mode = base.mode;
    this.newURI = base.newURI;
    this.errorCodes = FailureCodeTracker.copyOf(base.errorCodes);
    this.expectedMimeType = expectedMimeType;
    this.expectedSize = expectedSize;
    this.extraMessage = base.extraMessage;
    this.finalizedSizeAndMimeType = finalized;
  }
}

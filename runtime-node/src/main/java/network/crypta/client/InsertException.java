package network.crypta.client;

import java.io.Serial;
import java.util.HashMap;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.LowLevelPutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Exception indicating that a high-level content insert failed.
 *
 * <p>This type is the canonical error surface for insert operations invoked through the client
 * APIs. It summarizes the failure using a mode ({@link InsertExceptionMode}) and, when applicable,
 * augments it with an optional human-readable detail message, an optional cause, and a tracker of
 * low-level error codes captured during split-file inserts. For non-fatal failures the exception
 * may also carry the deterministic URI that would have been produced on success, allowing callers
 * to display or cache the prospective location of the data.
 *
 * <p>Instances are typically constructed close to the failure and propagated back to blocking or
 * callback-based client code. In some flows the exception is re-wrapped to attach a known
 * deterministic {@link FreenetURI} while preserving the original message, cause, suppressed
 * exceptions, and stack trace frames.
 *
 * <ul>
 *   <li>Represents insert failure mode and optional details.
 *   <li>May include collected error codes for split-file inserts.
 *   <li>Optionally exposes the would-be URI for non-fatal outcomes.
 *   <li>Designed for reporting and control flow; not all failures include a deep stack trace.
 * </ul>
 *
 * @see InsertExceptionMode
 */
public class InsertException extends Exception {
  private static final Logger LOG = LoggerFactory.getLogger(InsertException.class);

  private static final String LOG_INTERNAL_ERROR = "Internal error";
  private static final String LOG_CREATE_WITH_DETAILS = "Creating InsertException: {}: {}";
  private static final String LOG_CREATE = "Creating InsertException: {}";
  private static final String UNKNOWN_ERROR_PREFIX = "Unknown error ";

  @Serial private static final long serialVersionUID = -1106716067841151962L;

  /** Failure mode categorizing the insert error. */
  public final InsertExceptionMode mode;

  /**
   * Collect errors when there are multiple failures. The error mode will be FATAL_ERRORS_IN_BLOCKS
   * or TOO_MANY_RETRIES_IN_BLOCKS i.e. a splitfile failed.
   */
  private final FailureCodeTracker errorCodes;

  /**
   * If the error is not considered fatal, the URI the insert would have produced on success, when
   * known. May be {@code null} if the URI was not computed.
   */
  private final FreenetURI uri;

  /**
   * Optional human-readable detail message associated with the failure. When a cause is supplied,
   * this is typically the {@linkplain Throwable#getMessage() cause message}.
   */
  public final String extra;

  /**
   * Returns the categorized failure mode of this exception.
   *
   * @return the non-null failure mode describing the insert error category.
   */
  public InsertExceptionMode getMode() {
    return mode;
  }

  // no static initialization required

  /**
   * Creates an exception with a failure mode, an additional detail message, and the expected URI.
   * The resulting {@link #getMessage()} combines the mode description and the message text.
   *
   * @param m the failure mode describing the category of error; must not be {@code null}.
   * @param msg human-readable detail describing the failure; may be {@code null} or empty when no
   *     extra context is available.
   * @param expectedURI the deterministic URI that would have been produced on success; may be
   *     {@code null} if not known or not applicable.
   */
  public InsertException(InsertExceptionMode m, String msg, FreenetURI expectedURI) {
    super(getMessage(m) + ": " + msg);
    extra = msg;
    mode = m;
    errorCodes = null;
    this.uri = expectedURI;
    if (mode == InsertExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_CREATE_WITH_DETAILS, getMessage(mode), msg, this);
  }

  /**
   * Creates an exception with only a failure mode and an expected URI. The message contains the
   * localized description for the mode.
   *
   * @param m the failure mode describing the category of error; must not be {@code null}.
   * @param expectedURI the deterministic URI that would have been produced on success; may be
   *     {@code null} if not known or not applicable.
   */
  public InsertException(InsertExceptionMode m, FreenetURI expectedURI) {
    super(getMessage(m));
    extra = null;
    mode = m;
    errorCodes = null;
    this.uri = expectedURI;
    if (mode == InsertExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_CREATE, getMessage(mode), this);
  }

  /**
   * Creates an exception with a failure mode, a cause, and the expected URI. The message combines
   * the mode description and the cause message.
   *
   * @param mode the failure mode describing the category of error; must not be {@code null}.
   * @param e the underlying cause explaining the failure; must not be {@code null}.
   * @param expectedURI the deterministic URI that would have been produced on success; may be
   *     {@code null} if not known or not applicable.
   */
  public InsertException(InsertExceptionMode mode, Throwable e, FreenetURI expectedURI) {
    super(getMessage(mode) + ": " + e.getMessage());
    extra = e.getMessage();
    this.mode = mode;
    errorCodes = null;
    initCause(e);
    this.uri = expectedURI;
    if (mode == InsertExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_CREATE_WITH_DETAILS, getMessage(mode), e, this);
  }

  /**
   * Creates an exception with a failure mode, an additional detail message, a cause, and the
   * expected URI. The message combines the mode description, the additional text, and the cause
   * message.
   *
   * @param mode the failure mode describing the category of error; must not be {@code null}.
   * @param message human-readable context explaining the operation that failed; may be {@code null}
   *     or empty when not applicable.
   * @param e the underlying cause explaining the failure; must not be {@code null}.
   * @param expectedURI the deterministic URI that would have been produced on success; may be
   *     {@code null} if not known or not applicable.
   */
  public InsertException(
      InsertExceptionMode mode, String message, Throwable e, FreenetURI expectedURI) {
    super(getMessage(mode) + ": " + message + ": " + e.getMessage());
    extra = e.getMessage();
    this.mode = mode;
    errorCodes = null;
    initCause(e);
    this.uri = expectedURI;
    if (mode == InsertExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_CREATE_WITH_DETAILS, getMessage(mode), e, this);
  }

  /**
   * Creates an exception with a failure mode, a tracker of low-level error codes gathered during a
   * split-file insert, and the expected URI.
   *
   * @param mode the failure mode describing the category of error; must not be {@code null}.
   * @param errorCodes the collected low-level error statistics; may be {@code null} when not
   *     applicable.
   * @param expectedURI the deterministic URI that would have been produced on success; may be
   *     {@code null} if not known or not applicable.
   */
  public InsertException(
      InsertExceptionMode mode, FailureCodeTracker errorCodes, FreenetURI expectedURI) {
    super(getMessage(mode));
    extra = null;
    this.mode = mode;
    this.errorCodes = errorCodes;
    this.uri = expectedURI;
    if (mode == InsertExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_CREATE, getMessage(mode), this);
  }

  /**
   * Creates an exception with a failure mode, an additional detail message, a tracker of error
   * codes, and the expected URI. The message contains the mode description and the additional text
   * when present.
   *
   * @param mode the failure mode describing the category of error; must not be {@code null}.
   * @param message human-readable context explaining the operation that failed; may be {@code null}
   *     or empty when not applicable.
   * @param errorCodes the collected low-level error statistics; may be {@code null} when not
   *     applicable.
   * @param expectedURI the deterministic URI that would have been produced on success; may be
   *     {@code null} if not known or not applicable.
   */
  public InsertException(
      InsertExceptionMode mode,
      String message,
      FailureCodeTracker errorCodes,
      FreenetURI expectedURI) {
    super(message == null ? getMessage(mode) : (getMessage(mode) + ": " + message));
    extra = message;
    this.mode = mode;
    this.errorCodes = errorCodes;
    this.uri = expectedURI;
    if (mode == InsertExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_CREATE, getMessage(mode), this);
  }

  /**
   * Creates an exception with only a failure mode. No additional detail message, tracker, or URI is
   * included.
   *
   * @param mode the failure mode describing the category of error; must not be {@code null}.
   */
  public InsertException(InsertExceptionMode mode) {
    super(getMessage(mode));
    extra = null;
    this.mode = mode;
    this.errorCodes = null;
    this.uri = null;
    if (mode == InsertExceptionMode.INTERNAL_ERROR) LOG.error(LOG_INTERNAL_ERROR, this);
    else if (LOG.isDebugEnabled()) LOG.debug(LOG_CREATE, getMessage(mode), this);
  }

  /**
   * Creates a copy of the given exception while preserving its message, failure mode, URI, and a
   * deep copy of the error-code tracker. The cause, if present, is also preserved.
   *
   * @param e the source exception to copy; must not be {@code null}.
   */
  public InsertException(InsertException e) {
    super(e.getMessage());
    extra = e.extra;
    mode = e.mode;
    errorCodes = FailureCodeTracker.copyOf(e.errorCodes);
    uri = e.uri;
  }

  /**
   * Creates a copy of the given exception, overriding the expected URI while preserving the
   * original message, mode, cause, suppressed exceptions, and stack trace. Useful when a
   * higher-level component learns the deterministic URI after the source exception has been created
   * and wants to propagate that information to callers.
   *
   * @param e the source exception to copy; must not be {@code null}.
   * @param expectedURI the deterministic URI that would have been produced on success; may be
   *     {@code null} when not known or not applicable.
   */
  public InsertException(InsertException e, FreenetURI expectedURI) {
    // Allow writable stack to copy original frames; we'll overwrite below.
    super(e.getMessage(), e.getCause(), /*enableSuppression*/ true, /*writableStackTrace*/ true);
    extra = e.extra;
    mode = e.mode;
    errorCodes = FailureCodeTracker.copyOf(e.errorCodes);
    uri = expectedURI;
    // Copy suppressed exceptions and the original stack trace frames.
    for (Throwable s : e.getSuppressed()) addSuppressed(s);
    setStackTrace(e.getStackTrace());
  }

  // Historical constructor retained for compatibility was unused; removed to avoid unused
  // parameter.

  /**
   * Constructs a new {@code InsertException} from a low-level put error code.
   *
   * @param e the low-level put exception containing an error code; must not be {@code null}.
   * @return an {@code InsertException} mapping the low-level code to an insert mode; returns an
   *     {@link InsertExceptionMode#INTERNAL_ERROR} with details for unknown codes.
   */
  public static InsertException constructFrom(LowLevelPutException e) {
    return switch (e.code) {
      case LowLevelPutException.COLLISION -> new InsertException(InsertExceptionMode.COLLISION);
      case LowLevelPutException.INTERNAL_ERROR ->
          new InsertException(InsertExceptionMode.INTERNAL_ERROR);
      case LowLevelPutException.REJECTED_OVERLOAD ->
          new InsertException(InsertExceptionMode.REJECTED_OVERLOAD);
      case LowLevelPutException.ROUTE_NOT_FOUND ->
          new InsertException(InsertExceptionMode.ROUTE_NOT_FOUND);
      case LowLevelPutException.ROUTE_REALLY_NOT_FOUND ->
          new InsertException(InsertExceptionMode.ROUTE_REALLY_NOT_FOUND);
      default -> {
        LOG.error("Unknown LowLevelPutException code {}", e.code, e);
        yield new InsertException(
            InsertExceptionMode.INTERNAL_ERROR, UNKNOWN_ERROR_PREFIX + e.code, null);
      }
    };
  }

  private static final HashMap<Integer, InsertExceptionMode> modes = new HashMap<>();

  /**
   * Enumerates high-level insert failure modes. The values are stable across versions and are used
   * for localization keys and error aggregation.
   */
  public enum InsertExceptionMode {

    /** Caller supplied a URI we cannot use */
    INVALID_URI(1),
    /** Failed to read from or write to a bucket; a kind of internal error */
    BUCKET_ERROR(2),
    /** Internal error of some sort */
    INTERNAL_ERROR(3),
    /** Downstream node was overloaded */
    REJECTED_OVERLOAD(4),
    /** Couldn't find enough nodes to send the data to */
    ROUTE_NOT_FOUND(5),
    /** There were fatal errors in a splitfile insert. */
    FATAL_ERRORS_IN_BLOCKS(6),
    /** Could not insert a splitfile because a block failed too many times */
    TOO_MANY_RETRIES_IN_BLOCKS(7),
    /** Not able to leave the node at all */
    ROUTE_REALLY_NOT_FOUND(8),
    /** Collided with pre-existing content */
    COLLISION(9),
    /** Cancelled by user */
    CANCELLED(10),
    /** Meta string used in the key (most probably '/') */
    META_STRINGS_NOT_SUPPORTED(11),
    /** Invalid binary blob data supplied so cannot insert it */
    BINARY_BLOB_FORMAT_ERROR(12),
    /** Too many files in a directory in a site insert */
    TOO_MANY_FILES(13),
    /** File being uploaded is bigger than maximum supported size */
    TOO_BIG(14);

    /**
     * Stable numeric code associated with the mode. Used for localization keys and to aggregate
     * error statistics. Values are in the range {@code [1, UPPER_LIMIT_ERROR_CODE)}.
     */
    public final int code;

    InsertExceptionMode(int code) {
      this.code = code;
      if (code < 0 || code >= UPPER_LIMIT_ERROR_CODE) throw new IllegalArgumentException();
      if (modes.containsKey(code)) throw new IllegalArgumentException();
      modes.put(code, this);
    }

    /**
     * Returns the enum value associated with the given numeric code.
     *
     * @param code numeric code in the range {@code [1, UPPER_LIMIT_ERROR_CODE)}.
     * @return the corresponding {@code InsertExceptionMode} value.
     * @throws IllegalArgumentException if the code is not mapped to a known mode.
     */
    public static InsertExceptionMode getByCode(int code) {
      if (modes.get(code) == null) throw new IllegalArgumentException();
      return modes.get(code);
    }
  }

  /**
   * There will never be more error codes than this constant. Must not change, used for some data
   * structures.
   */
  public static final int UPPER_LIMIT_ERROR_CODE = 1024;

  /**
   * Returns the localized long description for the specified failure mode.
   *
   * @param mode the failure mode to describe; must not be {@code null}.
   * @return a non-empty localized string describing the mode, or a fallback string for unknown
   *     modes.
   */
  public static String getMessage(InsertExceptionMode mode) {
    // Localization currently uses numeric codes for keys; long error messages live under
    // "InsertException.longError.<code>".
    String ret = NodeL10n.getBase().getString("InsertException.longError." + mode.code);
    if (ret == null) return UNKNOWN_ERROR_PREFIX + mode;
    else return ret;
  }

  /**
   * Returns the localized short description for the specified failure mode.
   *
   * @param mode the failure mode to describe; must not be {@code null}.
   * @return a non-empty localized short label for the mode, or a fallback string for unknown modes.
   */
  public static String getShortMessage(InsertExceptionMode mode) {
    // Localization currently uses numeric codes for keys; short error messages live under
    // "InsertException.shortError.<code>".
    String ret = NodeL10n.getBase().getString("InsertException.shortError." + mode.code);
    if (ret == null) return UNKNOWN_ERROR_PREFIX + mode;
    else return ret;
  }

  /**
   * Returns whether this exception represents a fatal error. Non-fatal errors are likely to be
   * transient or may succeed if retried.
   *
   * @return {@code true} if the associated mode is considered fatal; otherwise {@code false}.
   */
  public boolean isFatal() {
    return isFatal(mode);
  }

  /**
   * Determines whether the specified failure mode is considered fatal.
   *
   * @param mode the failure mode to evaluate; must not be {@code null}.
   * @return {@code true} if the mode is fatal, indicating that retrying is unlikely to help;
   *     otherwise {@code false}.
   */
  public static boolean isFatal(InsertExceptionMode mode) {
    return switch (mode) {
      case INVALID_URI,
          FATAL_ERRORS_IN_BLOCKS,
          COLLISION,
          CANCELLED,
          META_STRINGS_NOT_SUPPORTED,
          BINARY_BLOB_FORMAT_ERROR,
          TOO_BIG,
          BUCKET_ERROR, // maybe. No point retrying.
          INTERNAL_ERROR ->
          true; // maybe. No point retrying.
      case REJECTED_OVERLOAD, TOO_MANY_RETRIES_IN_BLOCKS, ROUTE_NOT_FOUND, ROUTE_REALLY_NOT_FOUND ->
          false;
      default -> {
        String unknown = getMessage(mode);
        LOG.error("Error unknown to isFatal(): {}", unknown);
        yield false;
      }
    };
  }

  /**
   * Constructs an exception from aggregated low-level error codes, typically produced by a
   * split-file insert. When only a single code is present, the corresponding mode is used.
   * Otherwise, a summary fatal/non-fatal mode is derived.
   *
   * @param errors a tracker containing one or more error occurrences; may be {@code null} or empty
   *     to indicate success.
   * @return {@code null} when {@code errors} is {@code null} or empty; otherwise an exception with
   *     a mode derived from the tracker and carrying the tracker instance.
   */
  public static InsertException construct(FailureCodeTracker errors) {
    if (errors == null) return null;
    if (errors.isEmpty()) return null;
    if (errors.isOneCodeOnly()) {
      return new InsertException(errors.getFirstCodeInsert());
    }
    InsertExceptionMode mode;
    if (errors.isFatal(true)) mode = InsertExceptionMode.FATAL_ERRORS_IN_BLOCKS;
    else mode = InsertExceptionMode.TOO_MANY_RETRIES_IN_BLOCKS;
    return new InsertException(mode, errors, null);
  }

  /**
   * Returns the collected low-level error codes when available.
   *
   * @return the tracker instance when this exception was created from aggregated errors; otherwise
   *     {@code null}.
   */
  public FailureCodeTracker getErrorCodes() {
    return errorCodes;
  }

  /**
   * Returns the deterministic URI that the insert would have produced on success, when known. This
   * is typically populated for non-fatal outcomes after the key has been computed.
   *
   * @return the expected URI, or {@code null} when the URI was not determined or not applicable.
   */
  public FreenetURI getUri() {
    return uri;
  }
}
